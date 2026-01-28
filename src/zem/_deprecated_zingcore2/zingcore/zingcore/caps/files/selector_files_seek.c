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
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#define FILE_HANDLE_MAGIC 0xF17ECAFEu

typedef struct {
  uint32_t magic;
  FILE* f;
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
  if (!fh || fh->magic != FILE_HANDLE_MAGIC || !fh->f) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "handle");
  }

  int c_whence = 0;
  if (whence == 0) c_whence = SEEK_SET;
  else if (whence == 1) c_whence = SEEK_CUR;
  else if (whence == 2) c_whence = SEEK_END;
  else return emit->future_fail(ctx, future_id, "t_async_bad_params", "whence");

  fflush(fh->f);
  if (fseek(fh->f, (long)offset, c_whence) != 0) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "seek");
  }

  long pos = ftell(fh->f);
  if (pos < 0) return emit->future_fail(ctx, future_id, "t_file_not_found", "tell");

  if ((fh->mode == 2 || fh->mode == 3)) {
    int fd = fileno(fh->f);
    struct stat st;
    if (fd >= 0 && fstat(fd, &st) == 0 && st.st_size >= 0 && pos > st.st_size) {
      if (ftruncate(fd, (off_t)pos) != 0) {
        return emit->future_fail(ctx, future_id, "t_async_overflow", "extend");
      }
    }
  }
  /* NOTE: While the host can compute and return new_pos, the guest currently
     uses a fixed-size Buffer slab pool for temporaries, and some programs
     allocate many Buffers while awaiting multiple futures. Returning a value
     encourages decoding into tiny Buffers and increases sensitivity to that
     pool. Keep seek as a cursor-side effect for now. */
  return emit->future_ok(ctx, future_id, NULL, 0);
}

static int files_seek_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_seek = {
  .cap_kind = "file",
  .cap_name = "fs",
  .selector = "files.seek.v1",
  .invoke = files_seek_invoke,
  .cancel = files_seek_cancel,
};

__attribute__((constructor))
static void files_seek_autoreg(void) {
  zi_async_register(&sel_files_seek);
}
