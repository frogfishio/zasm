/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "host_abi.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static int bounds_ok(size_t ptr, size_t len, size_t size) {
  // Host-side guardrails: this local harness should never read/write past guest memory.
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

static wasm_trap_t* trapf(const char* fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  return wasmtime_trap_new(buf, strlen(buf));
}

static void format_bytes(char* out, size_t out_len, uint64_t bytes) {
  if (bytes % (1024ull * 1024ull * 1024ull) == 0) {
    snprintf(out, out_len, "%lluGB", (unsigned long long)(bytes / (1024ull * 1024ull * 1024ull)));
  } else if (bytes % (1024ull * 1024ull) == 0) {
    snprintf(out, out_len, "%lluMB", (unsigned long long)(bytes / (1024ull * 1024ull)));
  } else if (bytes % 1024ull == 0) {
    snprintf(out, out_len, "%lluKB", (unsigned long long)(bytes / 1024ull));
  } else {
    snprintf(out, out_len, "%lluB", (unsigned long long)bytes);
  }
}

static void write_u16_le(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void write_u32_le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
  p[2] = (uint8_t)((v >> 16) & 0xff);
  p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void allocs_add(zrun_abi_env_t* e, size_t ptr) {
  if (e->allocs_n == e->allocs_cap) {
    size_t cap = e->allocs_cap ? e->allocs_cap * 2 : 8;
    e->allocs = (size_t*)realloc(e->allocs, cap * sizeof(*e->allocs));
    e->allocs_cap = cap;
  }
  e->allocs[e->allocs_n++] = ptr;
}

static int allocs_remove(zrun_abi_env_t* e, size_t ptr) {
  for (size_t i = 0; i < e->allocs_n; i++) {
    if (e->allocs[i] == ptr) {
      e->allocs[i] = e->allocs[e->allocs_n - 1];
      e->allocs_n--;
      return 1;
    }
  }
  return 0;
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

wasm_trap_t* zrun_req_read(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 3 || nresults < 1) return NULL;

  int32_t ptr = args[1].of.i32;
  int32_t cap = args[2].of.i32;
  results[0].kind = WASMTIME_I32;
  tracef(e, "req_read(req=%d, ptr=%d, cap=%d)", args[0].of.i32, ptr, cap);

  if (ptr < 0 || cap < 0) {
    if (e->strict) return trap_msg("zrun: req_read invalid args");
    results[0].of.i32 = -1; return NULL;
  }

  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) {
    if (e->strict) return trap_msg("zrun: req_read missing memory export");
    results[0].of.i32 = -1; return NULL;
  }

  size_t mem_size = 0;
  uint8_t* data = mem_data(caller, &mem, &mem_size);
  size_t u_ptr = (size_t)ptr;
  size_t u_cap = (size_t)cap;
  if (!bounds_ok(u_ptr, u_cap, mem_size)) {
    if (e->strict) return trap_msg("zrun: req_read OOB");
    results[0].of.i32 = -1; return NULL;
  }

  size_t nread = fread(data + u_ptr, 1, u_cap, stdin);
  if (ferror(stdin)) {
    clearerr(stdin);
    if (e->strict) return trap_msg("zrun: req_read I/O error");
    results[0].of.i32 = -1; return NULL;
  }

  results[0].of.i32 = (int32_t)nread;
  tracef(e, "req_read -> %d", results[0].of.i32);
  return NULL;
}

wasm_trap_t* zrun_res_write(void* env, wasmtime_caller_t* caller,
                           const wasmtime_val_t* args, size_t nargs,
                           wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 3 || nresults < 1) return NULL;

  int32_t ptr = args[1].of.i32;
  int32_t len = args[2].of.i32;
  results[0].kind = WASMTIME_I32;
  tracef(e, "res_write(res=%d, ptr=%d, len=%d)", args[0].of.i32, ptr, len);

  if (getenv("ZRUN_FORCE_OUT_ERROR")) {
    if (e->strict) return trap_msg("zrun: res_write forced error");
    results[0].of.i32 = -1;
    return NULL;
  }

  if (ptr < 0 || len < 0) {
    if (e->strict) return trap_msg("zrun: res_write invalid args");
    results[0].of.i32 = -1; return NULL;
  }

  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) {
    if (e->strict) return trap_msg("zrun: res_write missing memory export");
    results[0].of.i32 = -1; return NULL;
  }

  size_t mem_size = 0;
  uint8_t* data = mem_data(caller, &mem, &mem_size);
  size_t u_ptr = (size_t)ptr;
  size_t u_len = (size_t)len;
  if (!bounds_ok(u_ptr, u_len, mem_size)) {
    if (e->strict) return trap_msg("zrun: res_write OOB");
    results[0].of.i32 = -1; return NULL;
  }

  size_t nw = fwrite(data + u_ptr, 1, u_len, stdout);
  fflush(stdout);
  if (nw != u_len) {
    if (e->strict) return trap_msg("zrun: res_write I/O error");
    results[0].of.i32 = -1; return NULL;
  }

  results[0].of.i32 = (int32_t)u_len;
  tracef(e, "res_write -> %d", results[0].of.i32);
  return NULL;
}

wasm_trap_t* zrun_res_end(void* env, wasmtime_caller_t* caller,
                         const wasmtime_val_t* args, size_t nargs,
                         wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  (void)caller;
  (void)args;
  (void)nargs;
  (void)results;
  (void)nresults;
  if (args && nargs >= 1) {
    tracef(e, "res_end(res=%d)", args[0].of.i32);
  } else {
    tracef(e, "res_end");
  }
  fflush(stdout);
  return NULL;
}

wasm_trap_t* zrun_log(void* env, wasmtime_caller_t* caller,
                     const wasmtime_val_t* args, size_t nargs,
                     wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  (void)results;
  (void)nresults;
  if (nargs < 4) return NULL;

  int32_t topic_ptr = args[0].of.i32;
  int32_t topic_len = args[1].of.i32;
  int32_t msg_ptr = args[2].of.i32;
  int32_t msg_len = args[3].of.i32;
  tracef(e, "log(topic_ptr=%d, topic_len=%d, msg_ptr=%d, msg_len=%d)",
         topic_ptr, topic_len, msg_ptr, msg_len);
  if (topic_ptr < 0 || topic_len < 0 || msg_ptr < 0 || msg_len < 0) {
    return e->strict ? trap_msg("zrun: log invalid args") : NULL;
  }

  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) return trap_msg("zrun: log missing memory export");

  size_t mem_size = 0;
  uint8_t* data = mem_data(caller, &mem, &mem_size);
  size_t u_topic_ptr = (size_t)topic_ptr;
  size_t u_topic_len = (size_t)topic_len;
  size_t u_msg_ptr = (size_t)msg_ptr;
  size_t u_msg_len = (size_t)msg_len;
  if (!bounds_ok(u_topic_ptr, u_topic_len, mem_size)) return trap_msg("zrun: log topic OOB");
  if (!bounds_ok(u_msg_ptr, u_msg_len, mem_size)) return trap_msg("zrun: log msg OOB");

  fwrite("[", 1, 1, stderr);
  fwrite(data + u_topic_ptr, 1, u_topic_len, stderr);
  fwrite("] ", 1, 2, stderr);
  fwrite(data + u_msg_ptr, 1, u_msg_len, stderr);
  fwrite("\n", 1, 1, stderr);
  return NULL;
}

wasm_trap_t* zrun_alloc(void* env, wasmtime_caller_t* caller,
                       const wasmtime_val_t* args, size_t nargs,
                       wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 1 || nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;

  int32_t size = args[0].of.i32;
  tracef(e, "alloc(size=%d)", size);
  if (size < 0) {
    if (e->strict) return trap_msg("zrun: alloc invalid size");
    results[0].of.i32 = -1; return NULL;
  }

  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) {
    if (e->strict) return trap_msg("zrun: alloc missing memory export");
    results[0].of.i32 = -1; return NULL;
  }

  size_t mem_size = 0;
  (void)mem_data(caller, &mem, &mem_size);

  // Simple bump allocator for local testing; relies on __heap_base from zld.
  if (!e->heap_init) {
    int32_t base = 0;
    if (!get_global_i32(caller, "__heap_base", &base)) {
      return trap_msg("zrun: missing __heap_base");
    }
    if (base < 0) base = 0;
    e->heap_ptr = (size_t)base;
    e->heap_init = 1;
  }

  size_t n = (size_t)size;
  size_t aligned = (n + 3u) & ~3u;
  if (e->heap_ptr + aligned > mem_size) {
    wasmtime_context_t* ctx = wasmtime_caller_context(caller);
    uint64_t page_size = wasmtime_memory_page_size(ctx, &mem);
    uint64_t needed = (uint64_t)e->heap_ptr + (uint64_t)aligned;
    uint64_t current_pages = page_size ? (mem_size / page_size) : 0;
    uint64_t needed_pages = page_size ? ((needed + page_size - 1) / page_size) : 0;
    uint64_t cap_bytes = e->mem_cap_bytes;
    uint64_t cap_pages = 0;
    if (cap_bytes > 0 && page_size > 0) {
      cap_pages = cap_bytes / page_size;
      if (needed_pages > cap_pages) {
        char cap_buf[32];
        format_bytes(cap_buf, sizeof(cap_buf), cap_bytes);
        return trapf("OOM: exceeded runner cap (cap=%s, requested grow beyond %llu pages)",
                     cap_buf, (unsigned long long)cap_pages);
      }
    }
    if (needed_pages > current_pages) {
      uint64_t prev = 0;
      wasmtime_error_t* err = wasmtime_memory_grow(ctx, &mem, needed_pages - current_pages, &prev);
      if (err) {
        wasmtime_error_delete(err);
        if (e->strict) return trap_msg("zrun: alloc memory grow failed");
        results[0].of.i32 = -1; return NULL;
      }
      mem_size = wasmtime_memory_data_size(ctx, &mem);
    }
    if (e->heap_ptr + aligned > mem_size) {
      if (e->strict) return trap_msg("zrun: alloc OOB");
      results[0].of.i32 = -1; return NULL;
    }
  }

  size_t out = e->heap_ptr;
  e->heap_ptr += aligned;
  results[0].of.i32 = (int32_t)out;
  if (e->strict) allocs_add(e, out);
  tracef(e, "alloc -> %d", results[0].of.i32);
  return NULL;
}

wasm_trap_t* zrun_free(void* env, wasmtime_caller_t* caller,
                      const wasmtime_val_t* args, size_t nargs,
                      wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  (void)caller;
  (void)results;
  (void)nresults;
  if (args && nargs >= 1) {
    int32_t ptr = args[0].of.i32;
    tracef(e, "free(ptr=%d)", ptr);
    if (ptr < 0) return e->strict ? trap_msg("zrun: free invalid ptr") : NULL;
    if (e->strict && !allocs_remove(e, (size_t)ptr)) {
      return trap_msg("zrun: free of unknown pointer");
    }
  } else {
    tracef(e, "free");
  }
  return NULL;
}

static int ctl_write_error(uint8_t* out, size_t cap, uint16_t op, uint32_t rid,
                           const char* trace, const char* msg) {
  const uint32_t trace_len = (uint32_t)strlen(trace);
  const uint32_t msg_len = (uint32_t)strlen(msg);
  const uint32_t cause_len = 0;
  const uint32_t payload_len = 4 + 4 + trace_len + 4 + msg_len + 4 + cause_len;
  const uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  memcpy(out + 0, "ZCL1", 4);
  write_u16_le(out + 4, 1);
  write_u16_le(out + 6, op);
  write_u32_le(out + 8, rid);
  write_u32_le(out + 12, 0);
  write_u32_le(out + 16, payload_len);
  out[20] = 0;
  out[21] = 0;
  out[22] = 0;
  out[23] = 0;
  write_u32_le(out + 24, trace_len);
  memcpy(out + 28, trace, trace_len);
  write_u32_le(out + 28 + trace_len, msg_len);
  memcpy(out + 32 + trace_len, msg, msg_len);
  write_u32_le(out + 32 + trace_len + msg_len, cause_len);
  return (int)frame_len;
}

wasm_trap_t* zrun_ctl(void* env, wasmtime_caller_t* caller,
                      const wasmtime_val_t* args, size_t nargs,
                      wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 4 || nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;

  int32_t req_ptr = args[0].of.i32;
  int32_t req_len = args[1].of.i32;
  int32_t resp_ptr = args[2].of.i32;
  int32_t resp_cap = args[3].of.i32;

  if (req_ptr < 0 || req_len < 0 || resp_ptr < 0 || resp_cap < 0) {
    if (e->strict) return trap_msg("zrun: ctl invalid args");
    results[0].of.i32 = -1; return NULL;
  }

  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) {
    if (e->strict) return trap_msg("zrun: ctl missing memory export");
    results[0].of.i32 = -1; return NULL;
  }
  size_t mem_size = 0;
  uint8_t* data = mem_data(caller, &mem, &mem_size);
  if (!bounds_ok((size_t)req_ptr, (size_t)req_len, mem_size) ||
      !bounds_ok((size_t)resp_ptr, (size_t)resp_cap, mem_size)) {
    if (e->strict) return trap_msg("zrun: ctl OOB");
    results[0].of.i32 = -1; return NULL;
  }

  if (req_len < 24) { results[0].of.i32 = -1; return NULL; }
  const uint8_t* req = data + req_ptr;
  if (memcmp(req, "ZCL1", 4) != 0) { results[0].of.i32 = -1; return NULL; }
  uint16_t v = (uint16_t)(req[4] | (req[5] << 8));
  uint16_t op = (uint16_t)(req[6] | (req[7] << 8));
  uint32_t rid = (uint32_t)(req[8] | (req[9] << 8) | (req[10] << 16) | (req[11] << 24));
  uint32_t payload_len = (uint32_t)(req[20] | (req[21] << 8) | (req[22] << 16) | (req[23] << 24));
  if (24u + payload_len > (uint32_t)req_len) { results[0].of.i32 = -1; return NULL; }

  uint8_t* out = data + resp_ptr;
  if (v != 1) {
    int n = ctl_write_error(out, (size_t)resp_cap, op, rid, "t_ctl_bad_version", "bad version");
    results[0].of.i32 = n;
    return NULL;
  }
  if (op != 1) {
    int n = ctl_write_error(out, (size_t)resp_cap, op, rid, "t_ctl_unknown_op", "unknown op");
    results[0].of.i32 = n;
    return NULL;
  }
  if (payload_len != 0) { results[0].of.i32 = -1; return NULL; }

  if (resp_cap < 28) { results[0].of.i32 = -1; return NULL; }
  memcpy(out + 0, "ZCL1", 4);
  write_u16_le(out + 4, 1);
  write_u16_le(out + 6, op);
  write_u32_le(out + 8, rid);
  write_u32_le(out + 12, 0);
  write_u32_le(out + 16, 8);
  out[20] = 1;
  out[21] = 0;
  out[22] = 0;
  out[23] = 0;
  write_u32_le(out + 24, 0);
  results[0].of.i32 = 28;
  return NULL;
}
