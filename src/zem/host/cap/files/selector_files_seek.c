/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../ctl_common.h"
#include "../../include/zi_async.h"
#include "../../include/zi_handles.h"
#include "files_store.h"
#include <string.h>

#define FILE_HANDLE_MAGIC 0xF17ECAFEu

typedef struct {
  uint32_t magic;
  zi_file_entry* entry;
  uint32_t pos;
  int mode; /* 1=read, 2=write, 3=append */
} file_handle_t;

static int files_seek_invoke(const zi_async_emit* emit, void* ctx,
                             const uint8_t* params, uint32_t params_len,
                             uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (params_len != 12) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "len");
  }
  int32_t handle = (int32_t)ctl_read_u32(params);
  int32_t offset = (int32_t)ctl_read_u32(params + 4);
  uint32_t whence = ctl_read_u32(params + 8);
  const zi_handle_slot_view_t* slot = zi_handle_get(handle);
  if (!slot || !slot->ctx) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "handle");
  }
  file_handle_t* fh = (file_handle_t*)slot->ctx;
  if (!fh || fh->magic != FILE_HANDLE_MAGIC || !fh->entry) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "handle");
  }
  uint64_t base = 0;
  if (whence == 0) {
    base = 0;
  } else if (whence == 1) {
    base = fh->pos;
  } else if (whence == 2) {
    base = fh->entry->len;
  } else {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "whence");
  }
  int64_t target = (int64_t)base + (int64_t)offset;
  if (target < 0) target = 0;
  uint32_t new_pos = (uint32_t)((target > (int64_t)UINT32_MAX) ? UINT32_MAX : target);
  if ((fh->mode == 2 || fh->mode == 3) && new_pos > fh->entry->len) {
    if (!zi_files_policy_allow("seek_extend", (const uint8_t*)fh->entry->id,
                               (uint32_t)strlen(fh->entry->id), 1)) {
      return emit->future_fail(ctx, future_id, "t_file_denied", "policy");
    }
    if (!zi_files_truncate((const uint8_t*)fh->entry->id,
                           (uint32_t)strlen(fh->entry->id), new_pos)) {
      return emit->future_fail(ctx, future_id, "t_async_overflow", "extend");
    }
  }
  if (new_pos > fh->entry->len) new_pos = fh->entry->len;
  fh->pos = new_pos;
  uint8_t payload[4];
  payload[0] = (uint8_t)(new_pos & 0xFF);
  payload[1] = (uint8_t)((new_pos >> 8) & 0xFF);
  payload[2] = (uint8_t)((new_pos >> 16) & 0xFF);
  payload[3] = (uint8_t)((new_pos >> 24) & 0xFF);
  return emit->future_ok(ctx, future_id, payload, sizeof(payload));
}

static int files_seek_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_seek = {
  .cap_kind = "file",
  .cap_name = "view",
  .selector = "files.seek.v1",
  .invoke = files_seek_invoke,
  .cancel = files_seek_cancel,
};

__attribute__((constructor))
static void files_seek_autoreg(void) {
  zi_async_register(&sel_files_seek);
}
