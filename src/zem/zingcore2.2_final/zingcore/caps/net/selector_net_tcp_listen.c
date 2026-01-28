/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../../caps/ctl_common.h"
#include "../../include/zi_async.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
  FLAG_PREFER_IPV6 = 1u << 1,
  FLAG_REUSEADDR = 1u << 3,
};

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return 0;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return 0;
  return 1;
}

static int net_tcp_listen_invoke(const zi_async_emit* emit, void* ctx,
                                 const uint8_t* params, uint32_t params_len,
                                 uint64_t req_id, uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len != 2 + 4) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "net.tcp.listen");
  }
  uint16_t port = ctl_read_u16(params);
  uint32_t flags = ctl_read_u32(params + 2);

  int af = (flags & FLAG_PREFER_IPV6) ? AF_INET6 : AF_INET;
  int fd = socket(af, SOCK_STREAM, 0);
  if (fd < 0) {
    return emit->future_fail(ctx, future_id, "t_net_unreachable", "socket");
  }
  if ((flags & FLAG_REUSEADDR) != 0) {
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  }
  if (!set_nonblocking(fd)) {
    close(fd);
    return emit->future_fail(ctx, future_id, "t_net_unreachable", "nonblock");
  }

  if (af == AF_INET) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
      close(fd);
      return emit->future_fail(ctx, future_id, "t_net_denied", "bind");
    }
  } else {
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port = htons(port);
    sa6.sin6_addr = in6addr_loopback;
    if (bind(fd, (struct sockaddr*)&sa6, sizeof(sa6)) < 0) {
      close(fd);
      return emit->future_fail(ctx, future_id, "t_net_denied", "bind");
    }
  }

  if (listen(fd, 8) < 0) {
    close(fd);
    return emit->future_fail(ctx, future_id, "t_net_unreachable", "listen");
  }

  /* Determine bound port (for port=0). */
  uint16_t bound = port;
  if (af == AF_INET) {
    struct sockaddr_in got;
    socklen_t gl = (socklen_t)sizeof(got);
    if (getsockname(fd, (struct sockaddr*)&got, &gl) == 0) {
      bound = ntohs(got.sin_port);
    }
  } else {
    struct sockaddr_in6 got;
    socklen_t gl = (socklen_t)sizeof(got);
    if (getsockname(fd, (struct sockaddr*)&got, &gl) == 0) {
      bound = ntohs(got.sin6_port);
    }
  }

  /* Payload: H4 handle, H4 hflags, HBYTES meta (meta = H2 port). */
  uint8_t payload[12 + 2];
  ctl_write_u32(payload + 0, (uint32_t)fd);
  ctl_write_u32(payload + 4, 0x5u); /* READABLE|ENDABLE */
  ctl_write_u32(payload + 8, 2u);   /* meta len */
  ctl_write_u16(payload + 12, bound);
  return emit->future_ok(ctx, future_id, payload, sizeof(payload));
}

static int net_tcp_listen_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_net_tcp_listen = {
  .cap_kind = "net",
  .cap_name = "tcp",
  .selector = "net.tcp.listen.v1",
  .invoke = net_tcp_listen_invoke,
  .cancel = net_tcp_listen_cancel,
};

__attribute__((constructor))
static void net_tcp_listen_autoreg(void) {
  zi_async_register(&sel_net_tcp_listen);
}

