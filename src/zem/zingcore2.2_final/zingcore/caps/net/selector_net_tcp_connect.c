/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../../caps/ctl_common.h"
#include "../../include/zi_async.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
  FLAG_ALLOW_DNS = 1u << 0,
  FLAG_PREFER_IPV6 = 1u << 1,
  FLAG_NODELAY = 1u << 2,
};

/* Policy hook; weak default allows all. */
__attribute__((weak))
int zi_net_policy_allow_connect(const uint8_t* host, uint32_t host_len, uint16_t port) {
  (void)host;
  (void)host_len;
  (void)port;
  return 1;
}

static int host_is_valid(const uint8_t *p, uint32_t len) {
  if (!p || len == 0) return 0;
  for (uint32_t i = 0; i < len; i++) {
    uint8_t c = p[i];
    if (c == 0) return 0;
    if (c < 0x20) return 0;
  }
  return 1;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return 0;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return 0;
  return 1;
}

static int set_nodelay(int fd) {
  int one = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
}

static int net_tcp_connect_invoke(const zi_async_emit* emit, void* ctx,
                                  const uint8_t* params, uint32_t params_len,
                                  uint64_t req_id, uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len < 4 + 2 + 4) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "net.tcp.connect");
  }
  uint32_t off = 0;
  uint32_t host_len = ctl_read_u32(params + off);
  off += 4;
  if (off + host_len + 2 + 4 != params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "net.tcp.connect");
  }
  const uint8_t* host = params + off;
  off += host_len;
  uint16_t port = ctl_read_u16(params + off);
  off += 2;
  uint32_t flags = ctl_read_u32(params + off);

  if (!host_is_valid(host, host_len) || port == 0) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "net.tcp.connect");
  }
  if (!zi_net_policy_allow_connect(host, host_len, port)) {
    return emit->future_fail(ctx, future_id, "t_net_denied", "policy");
  }
  if ((flags & FLAG_ALLOW_DNS) != 0) {
    if (!zi_async_tcp_dns_pending_add(ctx, future_id, host, host_len, port, flags)) {
      return emit->future_fail(ctx, future_id, "t_async_overflow", "dns_pending");
    }
    return 1;
  }

  int fd = -1;
  int af_first = (flags & FLAG_PREFER_IPV6) ? AF_INET6 : AF_INET;
  int af_second = (af_first == AF_INET6) ? AF_INET : AF_INET6;
  int afs[2] = { af_first, af_second };
  int last_err = EINVAL;

  for (int i = 0; i < 2; i++) {
    int af = afs[i];
    if (af == AF_INET) {
      struct sockaddr_in sa;
      memset(&sa, 0, sizeof(sa));
      sa.sin_family = AF_INET;
      sa.sin_port = htons(port);
      char tmp[128];
      if (host_len >= sizeof(tmp)) continue;
      memcpy(tmp, host, host_len);
      tmp[host_len] = '\0';
      if (inet_pton(AF_INET, tmp, &sa.sin_addr) != 1) continue;
      fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) { last_err = errno; continue; }
      if ((flags & FLAG_NODELAY) != 0) (void)set_nodelay(fd);
      if (!set_nonblocking(fd)) { last_err = errno; close(fd); fd = -1; continue; }
      int r = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
      if (r == 0) {
        int32_t handle = zi_async_tcp_register_fd(fd);
        if (handle < 0) { close(fd); return emit->future_fail(ctx, future_id, "t_async_failed", "handle_register"); }
        uint8_t payload[12];
        ctl_write_u32(payload + 0, (uint32_t)handle);
        ctl_write_u32(payload + 4, 0x7u);
        ctl_write_u32(payload + 8, 0u);
        return emit->future_ok(ctx, future_id, payload, sizeof(payload));
      }
      if (r < 0 && errno == EINPROGRESS) {
        if (!zi_async_tcp_connect_pending_add(ctx, future_id, fd)) {
          close(fd);
          return emit->future_fail(ctx, future_id, "t_async_overflow", "net_pending");
        }
        return 1;
      }
      last_err = errno;
      close(fd);
      fd = -1;
      continue;
    } else {
      struct sockaddr_in6 sa6;
      memset(&sa6, 0, sizeof(sa6));
      sa6.sin6_family = AF_INET6;
      sa6.sin6_port = htons(port);
      char tmp[256];
      if (host_len >= sizeof(tmp)) continue;
      memcpy(tmp, host, host_len);
      tmp[host_len] = '\0';
      if (inet_pton(AF_INET6, tmp, &sa6.sin6_addr) != 1) continue;
      fd = socket(AF_INET6, SOCK_STREAM, 0);
      if (fd < 0) { last_err = errno; continue; }
      if ((flags & FLAG_NODELAY) != 0) (void)set_nodelay(fd);
      if (!set_nonblocking(fd)) { last_err = errno; close(fd); fd = -1; continue; }
      int r = connect(fd, (struct sockaddr*)&sa6, sizeof(sa6));
      if (r == 0) {
        int32_t handle = zi_async_tcp_register_fd(fd);
        if (handle < 0) { close(fd); return emit->future_fail(ctx, future_id, "t_async_failed", "handle_register"); }
        uint8_t payload[12];
        ctl_write_u32(payload + 0, (uint32_t)handle);
        ctl_write_u32(payload + 4, 0x7u);
        ctl_write_u32(payload + 8, 0u);
        return emit->future_ok(ctx, future_id, payload, sizeof(payload));
      }
      if (r < 0 && errno == EINPROGRESS) {
        if (!zi_async_tcp_connect_pending_add(ctx, future_id, fd)) {
          close(fd);
          return emit->future_fail(ctx, future_id, "t_async_overflow", "net_pending");
        }
        return 1;
      }
      last_err = errno;
      close(fd);
      fd = -1;
      continue;
    }
  }

  (void)last_err;
  return emit->future_fail(ctx, future_id, "t_net_unreachable", "connect");
}

static int net_tcp_connect_cancel(void* ctx, uint64_t future_id) {
  (void)zi_async_tcp_dns_pending_cancel(ctx, future_id);
  (void)zi_async_tcp_connect_pending_cancel(ctx, future_id);
  return 1;
}

static const zi_async_selector sel_net_tcp_connect = {
  .cap_kind = "net",
  .cap_name = "tcp",
  .selector = "net.tcp.connect.v1",
  .invoke = net_tcp_connect_invoke,
  .cancel = net_tcp_connect_cancel,
};

__attribute__((constructor))
static void net_tcp_connect_autoreg(void) {
  zi_async_register(&sel_net_tcp_connect);
}
