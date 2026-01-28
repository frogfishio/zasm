/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../../caps/ctl_common.h"
#include "../../include/zi_async.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return 0;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return 0;
  return 1;
}

static int net_tcp_accept_invoke(const zi_async_emit* emit, void* ctx,
                                 const uint8_t* params, uint32_t params_len,
                                 uint64_t req_id, uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len != 4) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "net.tcp.accept");
  }
  int32_t listener = (int32_t)ctl_read_u32(params);
  if (listener < 3) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "net.tcp.accept");
  }
  (void)set_nonblocking(listener);
  int fd = accept(listener, NULL, NULL);
  if (fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      if (!zi_async_tcp_accept_pending_add(ctx, future_id, listener)) {
        return emit->future_fail(ctx, future_id, "t_async_overflow", "accept_pending");
      }
      return 1;
    }
    return emit->future_fail(ctx, future_id, "t_net_unreachable", "accept");
  }
  uint8_t payload[12];
  ctl_write_u32(payload + 0, (uint32_t)fd);
  ctl_write_u32(payload + 4, 0x7u);
  ctl_write_u32(payload + 8, 0u);
  return emit->future_ok(ctx, future_id, payload, sizeof(payload));
}

static int net_tcp_accept_cancel(void* ctx, uint64_t future_id) {
  (void)zi_async_tcp_accept_pending_cancel(ctx, future_id);
  return 1;
}

static const zi_async_selector sel_net_tcp_accept = {
  .cap_kind = "net",
  .cap_name = "tcp",
  .selector = "net.tcp.accept.v1",
  .invoke = net_tcp_accept_invoke,
  .cancel = net_tcp_accept_cancel,
};

__attribute__((constructor))
static void net_tcp_accept_autoreg(void) {
  zi_async_register(&sel_net_tcp_accept);
}

