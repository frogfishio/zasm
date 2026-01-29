/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include "../../include/zi_handles.h"
#include "files_store.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int files_debug_enabled(void) {
  return getenv("ZING_FILES_DEBUG") != NULL;
}

typedef struct {
  uint32_t magic;
  FILE* f;
  int mode; /* 1=read, 2=write(truncate/overwrite), 3=append */
} file_handle_t;

#define FILE_HANDLE_MAGIC 0xF17ECAFEu

static int file_read(void* ctx, void* buf, size_t len) {
  file_handle_t* h = (file_handle_t*)ctx;
  if (!h || !buf || h->magic != FILE_HANDLE_MAGIC) return -1;
  if (!h->f) return -1;
  if (len == 0) return 0;
  size_t n = fread(buf, 1, len, h->f);
  if (files_debug_enabled()) {
    fprintf(stderr, "file_read len=%zu n=%zu feof=%d ferror=%d\n", len, n,
            feof(h->f), ferror(h->f));
  }
  if (n == 0 && ferror(h->f)) return -1;
  return (int)n;
}

static int file_write(void* ctx, const void* buf, size_t len) {
  file_handle_t* h = (file_handle_t*)ctx;
  if (!h || h->magic != FILE_HANDLE_MAGIC || !h->f || (h->mode != 2 && h->mode != 3)) return -1;
  if (!buf || len == 0) return 0;
  size_t n = fwrite(buf, 1, len, h->f);
  if (n != len) return -1;
  return (int)n;
}

static void file_end(void* ctx) {
  if (!ctx) return;
  file_handle_t* h = (file_handle_t*)ctx;
  if (h->f) fclose(h->f);
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
  if (files_debug_enabled()) {
    fprintf(stderr, "files.open id_len=%u mode=%u\n", id_len, mode);
  }
  char full[1024];
  if (!zi_files_map_path(id, id_len, full, sizeof(full))) {
    return emit->future_fail(ctx, future_id, "t_file_denied", "path");
  }
  if (mode == 1 && access(full, F_OK) != 0) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "id");
  }

  file_handle_t* fh = (file_handle_t*)calloc(1, sizeof(file_handle_t));
  if (!fh) {
    return emit->future_fail(ctx, future_id, "t_async_overflow", "mem");
  }
  fh->mode = (int)mode;
  fh->magic = FILE_HANDLE_MAGIC;
  if ((mode == 2 || mode == 3) && !zi_files_policy_allow("open_write", id, id_len, 1)) {
    free(fh);
    return emit->future_fail(ctx, future_id, "t_file_denied", "policy");
  }

  const char* fmode = (mode == 1) ? "rb" : (mode == 2) ? "wb" : "rb+";
  fh->f = fopen(full, fmode);
  if (!fh->f && mode == 3) {
    /* READWRITE: if missing, create. */
    fh->f = fopen(full, "wb+");
  }
  if (!fh->f) {
    free(fh);
    return emit->future_fail(ctx, future_id, "t_file_not_found", strerror(errno));
  }
  if (mode == 1 && offset != 0) {
    if (fseek(fh->f, (long)offset, SEEK_SET) != 0) {
      fclose(fh->f);
      free(fh);
      return emit->future_fail(ctx, future_id, "t_file_not_found", "seek");
    }
  }
  int32_t handle = zi_handle_register(&k_file_ops, fh);
  if (handle < 0) {
    fclose(fh->f);
    free(fh);
    return emit->future_fail(ctx, future_id, "t_async_overflow", "handles");
  }
  if (files_debug_enabled()) {
    fprintf(stderr, "files.open handle=%d\n", handle);
  }
  uint8_t payload[16];
  payload[0] = (uint8_t)(handle & 0xFF);
  payload[1] = (uint8_t)((handle >> 8) & 0xFF);
  payload[2] = (uint8_t)((handle >> 16) & 0xFF);
  payload[3] = (uint8_t)((handle >> 24) & 0xFF);
  uint32_t hflags = (mode == 1) ? 0x1u : (mode == 2) ? 0x6u : 0x7u;
  payload[4] = (uint8_t)(hflags & 0xFF);
  payload[5] = (uint8_t)((hflags >> 8) & 0xFF);
  payload[6] = (uint8_t)((hflags >> 16) & 0xFF);
  payload[7] = (uint8_t)((hflags >> 24) & 0xFF);
  /* meta: current file length (u32) */
  payload[8] = 4; payload[9] = 0; payload[10] = 0; payload[11] = 0;
  struct stat st;
  uint32_t flen = 0;
  if (stat(full, &st) == 0 && st.st_size >= 0) flen = (uint32_t)st.st_size;
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
  .cap_name = "fs",
  .selector = "files.open.v1",
  .invoke = files_open_invoke,
  .cancel = files_open_cancel,
};

__attribute__((constructor))
static void files_open_autoreg(void) {
  zi_async_register(&sel_files_open);
}
