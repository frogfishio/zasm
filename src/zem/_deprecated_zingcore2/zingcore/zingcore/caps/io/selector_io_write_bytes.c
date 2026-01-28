/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

/* Params: HBYTES bytes */
static int io_write_bytes_invoke(const zi_async_emit *emit, void *ctx,
                                 const uint8_t *params, uint32_t params_len,
                                 uint64_t req_id, uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len < 4) {
    return emit->future_fail(ctx, future_id, "t_io_bad_params", "bytes len");
  }
  uint32_t len = read_u32_le(params);
  if (4u + len != params_len) {
    return emit->future_fail(ctx, future_id, "t_io_bad_params", "bytes");
  }
  const uint8_t *bytes = params + 4;

  if (len == 0) {
    return emit->future_ok(ctx, future_id, NULL, 0);
  }

  int ok = write_all(STDOUT_FILENO, bytes, len);
  if (!ok) {
    int err = errno;
    return emit->future_fail(ctx, future_id, "t_io_write_failed", strerror(err));
  }
  return emit->future_ok(ctx, future_id, NULL, 0);
}

static int io_write_bytes_cancel(void *ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_io_write_bytes = {
    .cap_kind = "io",
    .cap_name = "stdout",
    .selector = "io.write_bytes.v1",
    .invoke = io_write_bytes_invoke,
    .cancel = io_write_bytes_cancel,
};

__attribute__((constructor)) static void io_write_bytes_autoreg(void) {
  zi_async_register(&sel_io_write_bytes);
}

