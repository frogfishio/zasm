/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include "../../include/zi_handles.h"
#include "files_store.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t magic;
  zi_file_entry* entry;
  uint32_t pos;
  int mode; /* 1=read, 2=write(truncate/overwrite), 3=append */
} file_handle_t;

#define FILE_HANDLE_MAGIC 0xF17ECAFEu

static int file_read(void* ctx, void* buf, size_t len) {
  file_handle_t* h = (file_handle_t*)ctx;
  if (!h || !buf || h->magic != FILE_HANDLE_MAGIC) return -1;
  if (!h->entry) return -1;
  if (h->pos > h->entry->len) h->pos = h->entry->len;
  if (h->pos >= h->entry->len) return 0;
  uint32_t remaining = h->entry->len - h->pos;
  size_t n = (len < remaining) ? len : remaining;
  memcpy(buf, h->entry->data + h->pos, n);
  h->pos += (uint32_t)n;
  return (int)n;
}

static int file_write(void* ctx, const void* buf, size_t len) {
  file_handle_t* h = (file_handle_t*)ctx;
  if (!h || h->magic != FILE_HANDLE_MAGIC || !h->entry || (h->mode != 2 && h->mode != 3)) return -1;
  if (!buf || len == 0) return 0;
  uint32_t need = h->pos + (uint32_t)len;
  if (need > h->entry->cap) {
    uint32_t new_cap = h->entry->cap;
    while (new_cap < need) new_cap = (new_cap < 1024) ? (new_cap * 2) : (new_cap + 1024);
    uint8_t* nd = (uint8_t*)realloc(h->entry->data, new_cap);
    if (!nd) return -1;
    h->entry->data = nd;
    h->entry->cap = new_cap;
  }
  memcpy(h->entry->data + h->pos, buf, len);
  if (need > h->entry->len) h->entry->len = need;
  h->pos += (uint32_t)len;
  return (int)len;
}

static void file_end(void* ctx) {
  if (!ctx) return;
  free(ctx);
}

static const zi_handle_ops_t k_file_ops = {
  .read = file_read,
  .write = file_write,
  .end = file_end,
};

static int files_open_invoke(const zi_async_emit* emit, void* ctx,
                             const uint8_t* params, uint32_t params_len,
                             uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  uint32_t off = 0;
  if (params_len < 4) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "id len");
  }
  uint32_t id_len = (uint32_t)params[0] | ((uint32_t)params[1] << 8) |
                    ((uint32_t)params[2] << 16) | ((uint32_t)params[3] << 24);
  off += 4;
  if (off + id_len + 4 > params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "id bytes");
  }
  const uint8_t* id = params + off;
  off += id_len;
  uint32_t mode = (uint32_t)params[off] | ((uint32_t)params[off + 1] << 8) |
                  ((uint32_t)params[off + 2] << 16) | ((uint32_t)params[off + 3] << 24);
  off += 4;
  uint32_t offset = 0;
  if (off + 4 == params_len) {
    offset = (uint32_t)params[off] | ((uint32_t)params[off + 1] << 8) |
             ((uint32_t)params[off + 2] << 16) | ((uint32_t)params[off + 3] << 24);
    off += 4;
  }
  if (off != params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "trailing");
  }
  if (mode != 1 && mode != 2 && mode != 3) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "mode");
  }
  zi_file_entry* e = zi_files_find_mutable(id, id_len);
  if (!e) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "id");
  }
  file_handle_t* fh = (file_handle_t*)calloc(1, sizeof(file_handle_t));
  if (!fh) {
    return emit->future_fail(ctx, future_id, "t_async_overflow", "mem");
  }
  fh->entry = e;
  fh->mode = (int)mode;
  if (mode == 2) {
    /* overwrite: truncate first */
    e->len = 0;
    fh->pos = 0;
  } else if (mode == 3) {
    fh->pos = e->len;
  } else {
    fh->pos = (offset <= e->len) ? offset : e->len;
  }
  fh->magic = FILE_HANDLE_MAGIC;
  if ((mode == 2 || mode == 3) && !zi_files_policy_allow("open_write", id, id_len, 1)) {
    free(fh);
    return emit->future_fail(ctx, future_id, "t_file_denied", "policy");
  }
  int32_t handle = zi_handle_register(&k_file_ops, fh);
  if (handle < 0) {
    free(fh);
    return emit->future_fail(ctx, future_id, "t_async_overflow", "handles");
  }
  uint8_t payload[16];
  payload[0] = (uint8_t)(handle & 0xFF);
  payload[1] = (uint8_t)((handle >> 8) & 0xFF);
  payload[2] = (uint8_t)((handle >> 16) & 0xFF);
  payload[3] = (uint8_t)((handle >> 24) & 0xFF);
  uint32_t hflags = (mode == 1) ? 0x1u : 0x3u;
  payload[4] = (uint8_t)(hflags & 0xFF);
  payload[5] = (uint8_t)((hflags >> 8) & 0xFF);
  payload[6] = (uint8_t)((hflags >> 16) & 0xFF);
  payload[7] = (uint8_t)((hflags >> 24) & 0xFF);
  /* meta: current file length (u32) */
  payload[8] = 4; payload[9] = 0; payload[10] = 0; payload[11] = 0;
  uint32_t flen = e->len;
  payload[12] = (uint8_t)(flen & 0xFF);
  payload[13] = (uint8_t)((flen >> 8) & 0xFF);
  payload[14] = (uint8_t)((flen >> 16) & 0xFF);
  payload[15] = (uint8_t)((flen >> 24) & 0xFF);
  return emit->future_ok(ctx, future_id, payload, sizeof(payload));
}

static int files_open_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_open = {
  .cap_kind = "file",
  .cap_name = "view",
  .selector = "files.open.v1",
  .invoke = files_open_invoke,
  .cancel = files_open_cancel,
};

__attribute__((constructor))
static void files_open_autoreg(void) {
  zi_async_register(&sel_files_open);
}
