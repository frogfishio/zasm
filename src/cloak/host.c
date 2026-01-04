/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

static zcloak_env_t* g_env = NULL;

static int bounds_ok(size_t ptr, size_t len, size_t size) {
  if (ptr > size) return 0;
  if (len > size - ptr) return 0;
  return 1;
}

static void tracef(zcloak_env_t* e, const char* fmt, ...) {
  if (!e || !e->trace) return;
  va_list ap;
  va_start(ap, fmt);
  fputs("zcloak trace: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

static void fault(zcloak_env_t* e, const char* msg) {
  if (!e || !e->strict) return;
  e->faulted = 1;
  snprintf(e->fault_msg, sizeof(e->fault_msg), "%s", msg ? msg : "zcloak: fault");
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

static uint16_t read_u16_le(const uint8_t* p) {
  return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_u32_le(const uint8_t* p) {
  return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static void allocs_add(zcloak_env_t* e, size_t ptr) {
  if (e->allocs_n == e->allocs_cap) {
    size_t cap = e->allocs_cap ? e->allocs_cap * 2 : 8;
    e->allocs = (size_t*)realloc(e->allocs, cap * sizeof(*e->allocs));
    e->allocs_cap = cap;
  }
  e->allocs[e->allocs_n++] = ptr;
}

static int allocs_remove(zcloak_env_t* e, size_t ptr) {
  for (size_t i = 0; i < e->allocs_n; i++) {
    if (e->allocs[i] == ptr) {
      e->allocs[i] = e->allocs[e->allocs_n - 1];
      e->allocs_n--;
      return 1;
    }
  }
  return 0;
}

static int32_t cloak_req_read(int32_t req, int32_t ptr, int32_t cap) {
  zcloak_env_t* e = g_env;
  if (!e || !e->mem) return -1;
  tracef(e, "req_read(req=%d, ptr=%d, cap=%d)", req, ptr, cap);
  if (cap == 0) return 0;
  if (ptr < 0 || cap < 0) {
    fault(e, "zcloak: req_read invalid args");
    return -1;
  }
  size_t u_ptr = (size_t)ptr;
  size_t u_cap = (size_t)cap;
  if (!bounds_ok(u_ptr, u_cap, e->mem_cap)) {
    fault(e, "zcloak: req_read OOB");
    return -1;
  }
  size_t nread = fread(e->mem + u_ptr, 1, u_cap, stdin);
  if (ferror(stdin)) {
    clearerr(stdin);
    fault(e, "zcloak: req_read I/O error");
    return -1;
  }
  tracef(e, "req_read -> %zu", nread);
  return (int32_t)nread;
}

static int32_t cloak_res_write(int32_t res, int32_t ptr, int32_t len) {
  zcloak_env_t* e = g_env;
  if (!e || !e->mem) return -1;
  tracef(e, "res_write(res=%d, ptr=%d, len=%d)", res, ptr, len);

  if (getenv("ZRUN_FORCE_OUT_ERROR")) {
    fault(e, "zcloak: res_write forced error");
    return -1;
  }

  if (len == 0) return 0;
  if (ptr < 0 || len < 0) {
    fault(e, "zcloak: res_write invalid args");
    return -1;
  }
  size_t u_ptr = (size_t)ptr;
  size_t u_len = (size_t)len;
  if (!bounds_ok(u_ptr, u_len, e->mem_cap)) {
    fault(e, "zcloak: res_write OOB");
    return -1;
  }
  size_t nw = fwrite(e->mem + u_ptr, 1, u_len, stdout);
  fflush(stdout);
  if (nw != u_len) {
    fault(e, "zcloak: res_write I/O error");
    return -1;
  }
  tracef(e, "res_write -> %zu", nw);
  return (int32_t)nw;
}

static void cloak_res_end(int32_t res) {
  zcloak_env_t* e = g_env;
  (void)res;
  if (!e) return;
  tracef(e, "res_end(res=%d)", res);
  fflush(stdout);
}

static void cloak_log(int32_t topic_ptr, int32_t topic_len, int32_t msg_ptr, int32_t msg_len) {
  zcloak_env_t* e = g_env;
  if (!e || !e->mem) return;
  tracef(e, "log(topic_ptr=%d, topic_len=%d, msg_ptr=%d, msg_len=%d)",
         topic_ptr, topic_len, msg_ptr, msg_len);
  if (topic_ptr < 0 || topic_len < 0 || msg_ptr < 0 || msg_len < 0) return;
  size_t u_topic_ptr = (size_t)topic_ptr;
  size_t u_topic_len = (size_t)topic_len;
  size_t u_msg_ptr = (size_t)msg_ptr;
  size_t u_msg_len = (size_t)msg_len;
  if (!bounds_ok(u_topic_ptr, u_topic_len, e->mem_cap)) return;
  if (!bounds_ok(u_msg_ptr, u_msg_len, e->mem_cap)) return;
  fwrite("[", 1, 1, stderr);
  fwrite(e->mem + u_topic_ptr, 1, u_topic_len, stderr);
  fwrite("] ", 1, 2, stderr);
  fwrite(e->mem + u_msg_ptr, 1, u_msg_len, stderr);
  fwrite("\n", 1, 1, stderr);
}

static int32_t cloak_alloc(int32_t size) {
  zcloak_env_t* e = g_env;
  if (!e || !e->mem) return -1;
  tracef(e, "alloc(size=%d)", size);
  if (size < 0) {
    fault(e, "zcloak: alloc invalid size");
    return -1;
  }
  if (size == 0) {
    tracef(e, "alloc -> 0");
    return 0;
  }
  int32_t out = lembeh_bump_alloc(&e->bump, size);
  if (out < 0) {
    fault(e, "zcloak: alloc OOB");
    return -1;
  }
  if (e->strict && out > 0) allocs_add(e, (size_t)out);
  tracef(e, "alloc -> %d", out);
  return out;
}

static void cloak_free(int32_t ptr) {
  zcloak_env_t* e = g_env;
  if (!e) return;
  tracef(e, "free(ptr=%d)", ptr);
  if (ptr < 0) {
    fault(e, "zcloak: free invalid ptr");
    return;
  }
  if (ptr == 0) return;
  if (e->strict && !allocs_remove(e, (size_t)ptr)) {
    fault(e, "zcloak: free of unknown pointer");
  }
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

static int32_t cloak_ctl(int32_t req_ptr, int32_t req_len, int32_t resp_ptr, int32_t resp_cap) {
  zcloak_env_t* e = g_env;
  if (!e || !e->mem) return -1;
  if (req_ptr < 0 || req_len < 0 || resp_ptr < 0 || resp_cap < 0) {
    fault(e, "zcloak: ctl invalid args");
    return -1;
  }
  size_t u_req_ptr = (size_t)req_ptr;
  size_t u_req_len = (size_t)req_len;
  size_t u_resp_ptr = (size_t)resp_ptr;
  size_t u_resp_cap = (size_t)resp_cap;
  if (!bounds_ok(u_req_ptr, u_req_len, e->mem_cap) ||
      !bounds_ok(u_resp_ptr, u_resp_cap, e->mem_cap)) {
    fault(e, "zcloak: ctl OOB");
    return -1;
  }

  if (req_len < 24) return -1;
  const uint8_t* req = e->mem + u_req_ptr;
  uint16_t v = read_u16_le(req + 4);
  uint16_t op = read_u16_le(req + 6);
  uint32_t rid = read_u32_le(req + 8);
  uint32_t payload_len = read_u32_le(req + 20);
  uint8_t* out = e->mem + u_resp_ptr;

  if (memcmp(req, "ZCL1", 4) != 0) {
    return ctl_write_error(out, u_resp_cap, op, rid, "t_ctl_bad_frame", "bad frame");
  }
  if (24u + payload_len > (uint32_t)req_len) {
    return ctl_write_error(out, u_resp_cap, op, rid, "t_ctl_bad_frame", "bad frame");
  }
  if (v != 1) {
    return ctl_write_error(out, u_resp_cap, op, rid, "t_ctl_bad_version", "bad version");
  }
  if (op != 1) {
    return ctl_write_error(out, u_resp_cap, op, rid, "t_ctl_unknown_op", "unknown op");
  }
  if (payload_len != 0) return -1;

  if (u_resp_cap < 28) return -1;
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
  return 28;
}

static const lembeh_host_vtable_t g_host = {
  .req_read = cloak_req_read,
  .res_write = cloak_res_write,
  .res_end = cloak_res_end,
  .log = cloak_log,
  .alloc = cloak_alloc,
  .free = cloak_free,
  .ctl = cloak_ctl
};

void zcloak_env_init(zcloak_env_t* env, uint8_t* mem, size_t mem_cap,
                     uint64_t mem_cap_bytes, int trace, int strict) {
  if (!env) return;
  memset(env, 0, sizeof(*env));
  env->mem = mem;
  env->mem_cap = mem_cap;
  env->mem_cap_bytes = mem_cap_bytes;
  env->trace = trace;
  env->strict = strict;
  env->faulted = 0;
  env->fault_msg[0] = '\0';
  lembeh_bump_init(&env->bump, mem, mem_cap, 8);
  g_env = env;
  lembeh_bind_host(&g_host);
}

const lembeh_host_vtable_t* zcloak_host_vtable(void) {
  return &g_host;
}

int zcloak_env_faulted(const zcloak_env_t* env, const char** out_msg) {
  if (!env || !env->faulted) return 0;
  if (out_msg) *out_msg = env->fault_msg;
  return 1;
}
