/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
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

static void write_u32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xffu);
  p[1] = (uint8_t)((v >> 8) & 0xffu);
  p[2] = (uint8_t)((v >> 16) & 0xffu);
  p[3] = (uint8_t)((v >> 24) & 0xffu);
}

/* Params: I32LE (4 bytes) */
static int io_write_i32_invoke(const zi_async_emit *emit, void *ctx,
                               const uint8_t *params, uint32_t params_len,
                               uint64_t req_id, uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len != 4) {
    return emit->future_fail(ctx, future_id, "t_io_bad_params", "i32");
  }
  int32_t v = (int32_t)read_u32_le(params);

  char tmp[32];
  int n = snprintf(tmp, sizeof(tmp), "%" PRId32, v);
  if (n < 0 || (size_t)n >= sizeof(tmp)) {
    return emit->future_fail(ctx, future_id, "t_io_format_failed", "i32");
  }
  if (n == 0) {
    uint8_t pl[4];
    write_u32_le(pl, 0);
    return emit->future_ok(ctx, future_id, pl, sizeof(pl));
  }
  if (!write_all(STDOUT_FILENO, (const uint8_t *)tmp, (uint32_t)n)) {
    int err = errno;
    return emit->future_fail(ctx, future_id, "t_io_write_failed", strerror(err));
  }
  uint8_t pl[4];
  write_u32_le(pl, (uint32_t)n);
  return emit->future_ok(ctx, future_id, pl, sizeof(pl));
}

static int io_write_i32_cancel(void *ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_io_write_i32 = {
    .cap_kind = "io",
    .cap_name = "stdout",
    .selector = "io.write_i32.v1",
    .invoke = io_write_i32_invoke,
    .cancel = io_write_i32_cancel,
};

__attribute__((constructor)) static void io_write_i32_autoreg(void) {
  zi_async_register(&sel_io_write_i32);
}
