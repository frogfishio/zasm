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
#include "cap/ctl_common.h"
#include "include/zi_caps.h"
#include "include/zi_handles.h"
#include "include/zi_async.h"
#include <limits.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

enum {
  TAG_STR = 3,
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

static uint64_t zi_hash64_fnv1a(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 1469598103934665603ull;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ull;
  }
  return h;
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
typedef struct {
  const zi_handle_ops_t* ops;
  void* ctx;
  int in_use;
} zi_handle_slot_t;

static zi_handle_slot_t g_handles[ZI_HANDLE_MAX];
static int32_t g_handle_next = 3;

int32_t zi_handle_register(const zi_handle_ops_t* ops, void* ctx) {
  if (!ops || !ops->read || !ops->write) return -1;
  for (int i = 0; i < ZI_HANDLE_MAX; i++) {
    int32_t h = g_handle_next;
    g_handle_next++;
    if (g_handle_next >= ZI_HANDLE_MAX) g_handle_next = 3;
    if (h < 3) h = 3;
    if (h >= ZI_HANDLE_MAX) continue;
    if (!g_handles[h].in_use) {
      g_handles[h].in_use = 1;
      g_handles[h].ops = ops;
      g_handles[h].ctx = ctx;
      return h;
    }
  }
  return -1;
}

void zi_handle_unregister(int32_t handle) {
  if (handle < 0 || handle >= ZI_HANDLE_MAX) return;
  g_handles[handle].in_use = 0;
  g_handles[handle].ops = NULL;
  g_handles[handle].ctx = NULL;
}

const zi_handle_slot_view_t* zi_handle_get(int32_t handle) {
  if (handle < 0 || handle >= ZI_HANDLE_MAX) return NULL;
  if (!g_handles[handle].in_use) return NULL;
  return (const zi_handle_slot_view_t*)&g_handles[handle];
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

int32_t req_read(int32_t handle, void *ptr, size_t cap) {
  if (!ptr || cap <= 0) {
    return -1;
  }
  if (handle >= 0 && handle < ZI_HANDLE_MAX && g_handles[handle].in_use) {
    return g_handles[handle].ops->read(g_handles[handle].ctx, ptr, cap);
  }
  int fd = (handle == 0) ? STDIN_FILENO : handle;
  return clamp_ret(read(fd, ptr, cap));
}

int32_t res_write(int32_t handle, const void *ptr, size_t len) {
  if (!ptr || len <= 0) {
    return -1;
  }
  if (handle >= 0 && handle < ZI_HANDLE_MAX && g_handles[handle].in_use) {
    return g_handles[handle].ops->write(g_handles[handle].ctx, ptr, len);
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
  if (handle >= 0 && handle < ZI_HANDLE_MAX && g_handles[handle].in_use) {
    if (g_handles[handle].ops->end) {
      g_handles[handle].ops->end(g_handles[handle].ctx);
    }
    zi_handle_unregister(handle);
    return;
  }
  (void)handle;
  /* No-op for now; could flush/close in a richer runtime. */
}

static uint64_t zi_now_ms(void) {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) return 0;
  return (uint64_t)tv.tv_sec * 1000ull + (uint64_t)tv.tv_usec / 1000ull;
}

static int zi_telemetry_jsonl_enabled(void) {
  static int init = 0;
  static int enabled = 0;
  if (!init) {
    const char *v = getenv("ZI_TELEMETRY");
    enabled = (v && (strcmp(v, "jsonl") == 0 || strcmp(v, "ndjson") == 0));
    init = 1;
  }
  return enabled;
}

static int zi_telemetry_jsonl_ts_enabled(void) {
  static int init = 0;
  static int enabled = 0;
  if (!init) {
    const char *v = getenv("ZI_TELEMETRY_TS");
    enabled = (v && (strcmp(v, "1") == 0 || strcmp(v, "true") == 0 || strcmp(v, "yes") == 0));
    init = 1;
  }
  return enabled;
}

static uint64_t zi_telemetry_seq_next(void) {
  static uint64_t seq = 0;
  seq++;
  if (seq == 0) seq = 1;
  return seq;
}

static int zi_is_space(unsigned char ch) {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f';
}

static int zi_body_looks_like_json(const unsigned char *p, int32_t n) {
  if (!p || n <= 0) return 0;
  int32_t i = 0;
  while (i < n && zi_is_space(p[i])) i++;
  if (i >= n) return 0;
  unsigned char ch = p[i];
  if (ch == '{' || ch == '[' || ch == '\"') return 1;
  if (ch == '-' || (ch >= '0' && ch <= '9')) return 1;
  if (ch == 't' || ch == 'f' || ch == 'n') return 1;
  return 0;
}

static void zi_write_u64_stderr(uint64_t v) {
  char buf[32];
  int n = snprintf(buf, sizeof(buf), "%" PRIu64, v);
  if (n > 0) {
    write_all(STDERR_FILENO, buf, (size_t)n);
  } else {
    write_all(STDERR_FILENO, "0", 1);
  }
}

static void zi_write_json_string_stderr(const unsigned char *p, int32_t n) {
  static const char q[] = "\"";
  write_all(STDERR_FILENO, q, 1);
  if (p && n > 0) {
    for (int32_t i = 0; i < n; i++) {
      unsigned char ch = p[i];
      switch (ch) {
        case '"': write_all(STDERR_FILENO, "\\\"", 2); break;
        case '\\': write_all(STDERR_FILENO, "\\\\", 2); break;
        case '\b': write_all(STDERR_FILENO, "\\b", 2); break;
        case '\f': write_all(STDERR_FILENO, "\\f", 2); break;
        case '\n': write_all(STDERR_FILENO, "\\n", 2); break;
        case '\r': write_all(STDERR_FILENO, "\\r", 2); break;
        case '\t': write_all(STDERR_FILENO, "\\t", 2); break;
        default:
          if (ch < 0x20 || ch == 0x7F) {
            static const char hex[] = "0123456789abcdef";
            char esc[6] = {'\\', 'u', '0', '0', hex[(ch >> 4) & 0xF], hex[ch & 0xF]};
            write_all(STDERR_FILENO, esc, sizeof(esc));
          } else {
            write_all(STDERR_FILENO, &ch, 1);
          }
          break;
      }
    }
  }
  write_all(STDERR_FILENO, q, 1);
}

void telemetry(const char *topic_ptr, int32_t topic_len,
               const char *msg_ptr, int32_t msg_len) {
  if (zi_telemetry_jsonl_enabled()) {
    // JSONL/NDJSON for easy piping in dev.
    // Default shape: {"topic":"...","body":<raw json or "string">}\n
    write_all(STDERR_FILENO, "{", 1);
    write_all(STDERR_FILENO, "\"seq\":", 6);
    zi_write_u64_stderr(zi_telemetry_seq_next());
    write_all(STDERR_FILENO, ",", 1);
    if (zi_telemetry_jsonl_ts_enabled()) {
      // Optional host timestamp (nondeterministic by nature).
      write_all(STDERR_FILENO, "\"ts\":", 5);
      zi_write_u64_stderr(zi_now_ms());
      write_all(STDERR_FILENO, ",", 1);
    }

    write_all(STDERR_FILENO, "\"topic\":", 8);
    zi_write_json_string_stderr((const unsigned char *)topic_ptr, topic_len);
    write_all(STDERR_FILENO, ",\"body\":", 8);

    if (zi_body_looks_like_json((const unsigned char *)msg_ptr, msg_len)) {
      if (msg_ptr && msg_len > 0) write_all(STDERR_FILENO, msg_ptr, (size_t)msg_len);
      else write_all(STDERR_FILENO, "null", 4);
    } else {
      zi_write_json_string_stderr((const unsigned char *)msg_ptr, msg_len);
    }

    write_all(STDERR_FILENO, "}\\n", 2);
    return;
  }

  static const char k_sep[] = ": ";
  static const char k_newline[] = "\n";
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

int32_t _cap(int32_t idx) {
  (void)idx;
  /* No capabilities are exposed by this shim. */
  return -1;
}

/* Minimal entrypoint when linking without the platform CRT. */
/* None: we link against the system CRT and use the Zing-exported `main`. */
