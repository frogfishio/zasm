/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include "files_store.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint32_t read_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int write_all(int fd, const uint8_t *buf, uint32_t len) {
  uint32_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, buf + off, (size_t)(len - off));
    if (n <= 0) return 0;
    off += (uint32_t)n;
  }
  return 1;
}

static int files_write_all_path_invoke(const zi_async_emit *emit, void *ctx,
                                       const uint8_t *params,
                                       uint32_t params_len, uint64_t req_id,
                                       uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len < 8) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "path len");
  }
  uint32_t off = 0;
  uint32_t path_len = read_u32_le(params + off);
  off += 4;
  if (path_len == 0 || off + path_len + 4 > params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "path bytes");
  }
  const uint8_t *path_bytes = params + off;
  off += path_len;
  uint32_t data_len = read_u32_le(params + off);
  off += 4;
  if (off + data_len != params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "data bytes");
  }
  const uint8_t *data = params + off;

  char path[1024];
  if (!zi_files_map_path(path_bytes, path_len, path, sizeof(path))) {
    return emit->future_fail(ctx, future_id, "t_file_denied", "path");
  }

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  int err = errno;
  if (fd < 0) {
    return emit->future_fail(ctx, future_id, "t_file_io", strerror(err));
  }
  int ok = write_all(fd, data, data_len);
  err = errno;
  close(fd);
  if (!ok) {
    return emit->future_fail(ctx, future_id, "t_file_io", strerror(err));
  }
  return emit->future_ok(ctx, future_id, NULL, 0);
}

static int files_write_all_path_cancel(void *ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_write_all_path = {
    .cap_kind = "file",
    .cap_name = "fs",
    .selector = "fs.write_all_path.v1",
    .invoke = files_write_all_path_invoke,
    .cancel = files_write_all_path_cancel,
};

__attribute__((constructor)) static void files_write_all_path_autoreg(void) {
  zi_async_register(&sel_files_write_all_path);
}
