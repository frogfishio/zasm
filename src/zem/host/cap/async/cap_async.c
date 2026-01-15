/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Extracted async host capability logic (cap.async.v1) from cloak/host.c.
 * Handles ZAX1 framing, inline command processing, and the `_ctl` open path
 * for `kind="async", name="default"`.
 *
 * Note: This is a standalone extract for ABI work; it preserves the original
 * structures and helpers used in cloak/host.c but is not wired into zingcore.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
  HANDLE_NONE = 0,
  HANDLE_ASYNC = 1,
};

typedef struct {
  uint8_t* cmd;
  size_t cmd_len;
  size_t cmd_cap;
  uint8_t* read;
  size_t read_len;
  size_t read_cap;
  size_t read_pos;
} async_handle_t;

typedef struct {
  async_handle_t handles[64];
  uint8_t handle_kind[64];
  int next_handle;
} zcloak_env_t;

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

static uint64_t read_u64_le(const uint8_t* p) {
  uint64_t lo = read_u32_le(p);
  uint64_t hi = read_u32_le(p + 4);
  return lo | (hi << 32);
}

static void write_u64_le(uint8_t* p, uint64_t v) {
  write_u32_le(p, (uint32_t)(v & 0xffffffffu));
  write_u32_le(p + 4, (uint32_t)(v >> 32));
}

static int append_bytes(uint8_t** buf, size_t* len, size_t* cap,
                        const uint8_t* data, size_t n) {
  if (*len + n > *cap) {
    size_t next = *cap ? *cap * 2 : 64;
    while (next < *len + n) {
      next *= 2;
    }
    uint8_t* tmp = (uint8_t*)realloc(*buf, next);
    if (!tmp) return 0;
    *buf = tmp;
    *cap = next;
  }
  memcpy(*buf + *len, data, n);
  *len += n;
  return 1;
}

static int async_enqueue_frame(zcloak_env_t* e, int handle, uint16_t kind, uint16_t op,
                               uint64_t req_id, uint64_t future_id,
                               const uint8_t* payload, uint32_t payload_len) {
  if (handle < 0 || handle >= (int)(sizeof(e->handles) / sizeof(e->handles[0]))) {
    return 0;
  }
  uint8_t header[48];
  memcpy(header, "ZAX1", 4);
  write_u16_le(header + 4, 1);
  write_u16_le(header + 6, kind);
  write_u16_le(header + 8, op);
  write_u16_le(header + 10, 0);
  write_u64_le(header + 12, req_id);
  write_u64_le(header + 20, 0);
  write_u64_le(header + 28, 0);
  write_u64_le(header + 36, future_id);
  write_u32_le(header + 44, payload_len);
  if (!append_bytes(&e->handles[handle].read,
                    &e->handles[handle].read_len,
                    &e->handles[handle].read_cap,
                    header, sizeof(header))) {
    return 0;
  }
  if (payload_len > 0) {
    if (!append_bytes(&e->handles[handle].read,
                      &e->handles[handle].read_len,
                      &e->handles[handle].read_cap,
                      payload, payload_len)) {
      return 0;
    }
  }
  return 1;
}

static void async_emit_fail(zcloak_env_t* e, int handle, uint64_t req_id,
                            const char* code, const char* msg) {
  uint32_t code_len = (uint32_t)strlen(code);
  uint32_t msg_len = (uint32_t)strlen(msg);
  uint32_t payload_len = 8 + code_len + msg_len;
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return;
  write_u32_le(payload, code_len);
  write_u32_le(payload + 4, msg_len);
  memcpy(payload + 8, code, code_len);
  memcpy(payload + 8 + code_len, msg, msg_len);
  async_enqueue_frame(e, handle, 2, 102, req_id, 0, payload, payload_len);
  free(payload);
}

static void async_process_cmds(zcloak_env_t* e, int handle) {
  if (handle < 0 || handle >= (int)(sizeof(e->handles) / sizeof(e->handles[0]))) {
    return;
  }
  size_t pos = 0;
  uint8_t* buf = e->handles[handle].cmd;
  size_t len = e->handles[handle].cmd_len;
  while (len - pos >= 48) {
    const uint8_t* p = buf + pos;
    if (memcmp(p, "ZAX1", 4) != 0) {
      async_emit_fail(e, handle, 0, "t_async_bad_frame", "magic");
      e->handles[handle].cmd_len = 0;
      return;
    }
    uint16_t v = read_u16_le(p + 4);
    uint16_t kind = read_u16_le(p + 6);
    uint16_t op = read_u16_le(p + 8);
    uint64_t req_id = read_u64_le(p + 12);
    uint64_t future_id = read_u64_le(p + 36);
    uint32_t payload_len = read_u32_le(p + 44);
    if (payload_len > (1u << 20)) {
      async_emit_fail(e, handle, req_id, "t_async_bad_frame", "payload");
      e->handles[handle].cmd_len = 0;
      return;
    }
    if (v != 1 || kind != 1) {
      async_emit_fail(e, handle, req_id, "t_async_bad_frame", "header");
      e->handles[handle].cmd_len = 0;
      return;
    }
    if (len - pos < 48 + payload_len) break;
    if (req_id != 0) {
      async_enqueue_frame(e, handle, 2, 101, req_id, 0, NULL, 0);
    }
    if (op == 1) {
      uint8_t payload[7];
      write_u32_le(payload, 3);
      payload[4] = 'o';
      payload[5] = 'k';
      payload[6] = '\n';
      async_enqueue_frame(e, handle, 2, 110, req_id, future_id, payload, sizeof(payload));
    } else if (op == 2) {
      /* Cancel future: ACK already emitted above. */
    } else {
      async_emit_fail(e, handle, req_id, "t_async_unknown_op", "op");
    }
    pos += 48 + payload_len;
  }
  if (pos > 0) {
    memmove(buf, buf + pos, len - pos);
    e->handles[handle].cmd_len -= pos;
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

static int ctl_write_caps_open_ok(uint8_t* out, size_t cap, uint16_t op, uint32_t rid,
                                  uint32_t handle, uint32_t hflags) {
  const uint32_t payload_len = 4 + 12;
  const uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  memcpy(out + 0, "ZCL1", 4);
  write_u16_le(out + 4, 1);
  write_u16_le(out + 6, op);
  write_u32_le(out + 8, rid);
  write_u32_le(out + 12, 0);
  write_u32_le(out + 16, payload_len);
  out[20] = 1;
  out[21] = 0;
  out[22] = 0;
  out[23] = 0;
  write_u32_le(out + 24, handle);
  write_u32_le(out + 28, hflags);
  write_u32_le(out + 32, 0);
  return (int32_t)frame_len;
}

/*
 * `_ctl` async open path (excerpt from cloak_ctl):
 *   kind="async", name="default" -> allocate new handle with flags 1|2.
 *   Returns a caps.open OK frame or ctl error.
 */
static int ctl_handle_async_open(zcloak_env_t* e, uint8_t* out, size_t out_cap,
                                 uint16_t op, uint32_t rid,
                                 uint32_t kind_len, const uint8_t* kind,
                                 uint32_t name_len, const uint8_t* name) {
  if (!(kind_len == 5 && memcmp(kind, "async", 5) == 0 &&
        name_len == 7 && memcmp(name, "default", 7) == 0)) {
    return 0; /* not handled */
  }
  if (e->next_handle <= 0 ||
      e->next_handle >= (int)(sizeof(e->handles) / sizeof(e->handles[0]))) {
    return ctl_write_error(out, out_cap, op, rid, "t_ctl_overflow", "handles");
  }
  int handle = e->next_handle++;
  e->handle_kind[handle] = HANDLE_ASYNC;
  uint32_t hflags = 1u | 2u;
  return ctl_write_caps_open_ok(out, out_cap, op, rid, (uint32_t)handle, hflags);
}
