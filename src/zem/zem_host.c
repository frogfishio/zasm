/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "zem_host.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>

static ssize_t write_all(int fd, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  size_t total = 0;
  while (total < len) {
    ssize_t n = write(fd, p + total, len - total);
    if (n <= 0) return (total > 0) ? (ssize_t)total : -1;
    total += (size_t)n;
  }
  return (ssize_t)total;
}

static int32_t clamp_ret(ssize_t n) {
  if (n < 0) return -1;
  if (n > INT32_MAX) return INT32_MAX;
  return (int32_t)n;
}

int32_t res_write(int32_t handle, const void *ptr, size_t len) {
  if (!ptr || len == 0) return -1;
  int fd = handle;
  if (handle == 1) fd = STDOUT_FILENO;
  else if (handle == 2) fd = STDERR_FILENO;
  return clamp_ret(write_all(fd, ptr, len));
}

int32_t req_read(int32_t handle, void *ptr, size_t cap) {
  if (!ptr || cap == 0) return -1;
  int fd = (handle == 0) ? STDIN_FILENO : handle;
  return clamp_ret(read(fd, ptr, cap));
}

void res_end(int32_t handle) {
  (void)handle;
}

void telemetry(const char *topic_ptr, int32_t topic_len, const char *msg_ptr,
               int32_t msg_len) {
  static const char sep[] = ": ";
  static const char nl[] = "\n";

  if (topic_ptr && topic_len > 0) {
    (void)write_all(STDERR_FILENO, topic_ptr, (size_t)topic_len);
    (void)write_all(STDERR_FILENO, sep, sizeof(sep) - 1);
  }
  if (msg_ptr && msg_len > 0) {
    (void)write_all(STDERR_FILENO, msg_ptr, (size_t)msg_len);
  }
  (void)write_all(STDERR_FILENO, nl, sizeof(nl) - 1);
}

int32_t _ctl(const void *req_ptr, size_t req_len, void *resp_ptr,
             size_t resp_cap) {
  (void)req_ptr;
  (void)req_len;
  (void)resp_ptr;
  (void)resp_cap;
  return -1;
}

int32_t _cap(int32_t idx) {
  (void)idx;
  return -1;
}
