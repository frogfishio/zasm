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

enum { MAX_READ = 1024 * 1024 };

static uint32_t read_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int files_read_all_path_invoke(const zi_async_emit *emit, void *ctx,
                                      const uint8_t *params,
                                      uint32_t params_len, uint64_t req_id,
                                      uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len < 4) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "path len");
  }
  uint32_t path_len = read_u32_le(params);
  if (path_len == 0 || 4u + path_len != params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "path bytes");
  }
  const uint8_t *path_bytes = params + 4;

  char path[1024];
  if (!zi_files_map_path(path_bytes, path_len, path, sizeof(path))) {
    return emit->future_fail(ctx, future_id, "t_file_denied", "path");
  }

  int fd = open(path, O_RDONLY);
  int err = errno;
  if (fd < 0) {
    return emit->future_fail(ctx, future_id, "t_file_io", strerror(err));
  }

  uint8_t *buf = (uint8_t *)malloc(MAX_READ);
  if (!buf) {
    close(fd);
    return emit->future_fail(ctx, future_id, "t_async_failed", "oom");
  }
  ssize_t n = read(fd, buf, MAX_READ);
  err = errno;
  close(fd);
  if (n < 0) {
    free(buf);
    return emit->future_fail(ctx, future_id, "t_file_io", strerror(err));
  }
  int ok = emit->future_ok(ctx, future_id, buf, (uint32_t)n);
  free(buf);
  return ok;
}

static int files_read_all_path_cancel(void *ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_read_all_path = {
    .cap_kind = "file",
    .cap_name = "fs",
    .selector = "fs.read_all_path.v1",
    .invoke = files_read_all_path_invoke,
    .cancel = files_read_all_path_cancel,
};

__attribute__((constructor)) static void files_read_all_path_autoreg(void) {
  zi_async_register(&sel_files_read_all_path);
}
