/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../../../include/zi_async.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t handle;
  uint8_t buf[2048];
  uint32_t len;
  int in_use;
} net_conn_t;

#define NET_CONN_MAX 8
static net_conn_t g_conns[NET_CONN_MAX];

static net_conn_t* net_conn_alloc(void) {
  for (int i = 0; i < NET_CONN_MAX; i++) {
    if (!g_conns[i].in_use) {
      g_conns[i].in_use = 1;
      g_conns[i].handle = (uint32_t)(100 + i);
      g_conns[i].len = 0;
      return &g_conns[i];
    }
  }
  return NULL;
}

static net_conn_t* net_conn_find(uint32_t h) {
  for (int i = 0; i < NET_CONN_MAX; i++) {
    if (g_conns[i].in_use && g_conns[i].handle == h) return &g_conns[i];
  }
  return NULL;
}

static int net_connect_invoke(const zi_async_emit* emit, void* ctx,
                              const uint8_t* params, uint32_t params_len,
                              uint64_t req_id, uint64_t future_id) {
  (void)ctx; (void)req_id; (void)params; (void)params_len;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  /* params: none for loopback */
  if (params_len != 0) return emit->future_fail(ctx, future_id, "t_async_bad_params", "connect params");
  net_conn_t* c = net_conn_alloc();
  if (!c) return emit->future_fail(ctx, future_id, "t_net_unavailable", "no slots");
  uint8_t payload[12];
  payload[0] = (uint8_t)(c->handle & 0xFF);
  payload[1] = (uint8_t)((c->handle >> 8) & 0xFF);
  payload[2] = (uint8_t)((c->handle >> 16) & 0xFF);
  payload[3] = (uint8_t)((c->handle >> 24) & 0xFF);
  /* hflags: readable|writable */
  payload[4] = 0x3; payload[5] = 0; payload[6] = 0; payload[7] = 0;
  /* meta len */
  payload[8] = 0; payload[9] = 0; payload[10] = 0; payload[11] = 0;
  return emit->future_ok(ctx, future_id, payload, sizeof(payload));
}

static int net_send_invoke(const zi_async_emit* emit, void* ctx,
                           const uint8_t* params, uint32_t params_len,
                           uint64_t req_id, uint64_t future_id) {
  (void)ctx; (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (params_len < 8) return emit->future_fail(ctx, future_id, "t_async_bad_params", "send len");
  uint32_t h = (uint32_t)params[0] | ((uint32_t)params[1] << 8) |
               ((uint32_t)params[2] << 16) | ((uint32_t)params[3] << 24);
  uint32_t dlen = (uint32_t)params[4] | ((uint32_t)params[5] << 8) |
                  ((uint32_t)params[6] << 16) | ((uint32_t)params[7] << 24);
  if (8u + dlen != params_len) return emit->future_fail(ctx, future_id, "t_async_bad_params", "send bytes");
  net_conn_t* c = net_conn_find(h);
  if (!c) {
    c = net_conn_alloc();
    if (c) c->handle = h;
  }
  if (!c) return emit->future_fail(ctx, future_id, "t_net_not_found", "handle");
  if (dlen > sizeof(c->buf)) return emit->future_fail(ctx, future_id, "t_net_overflow", "payload");
  memcpy(c->buf, params + 8, dlen);
  c->len = dlen;
  uint8_t payload[4];
  payload[0] = (uint8_t)(dlen & 0xFF);
  payload[1] = (uint8_t)((dlen >> 8) & 0xFF);
  payload[2] = (uint8_t)((dlen >> 16) & 0xFF);
  payload[3] = (uint8_t)((dlen >> 24) & 0xFF);
  return emit->future_ok(ctx, future_id, payload, sizeof(payload));
}

static int net_recv_invoke(const zi_async_emit* emit, void* ctx,
                           const uint8_t* params, uint32_t params_len,
                           uint64_t req_id, uint64_t future_id) {
  (void)ctx; (void)req_id; (void)params; (void)params_len;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  static const char resp[] = "loop-data";
  uint32_t take = (uint32_t)(sizeof(resp) - 1);
  uint8_t payload[4 + sizeof(resp) - 1];
  payload[0] = (uint8_t)(take & 0xFF);
  payload[1] = (uint8_t)((take >> 8) & 0xFF);
  payload[2] = (uint8_t)((take >> 16) & 0xFF);
  payload[3] = (uint8_t)((take >> 24) & 0xFF);
  memcpy(payload + 4, resp, take);
  return emit->future_ok(ctx, future_id, payload, 4 + take);
}

static int net_cancel(void* ctx, uint64_t future_id) {
  (void)ctx; (void)future_id; return 1;
}

static const zi_async_selector sel_net_connect = {
  .cap_kind = "net",
  .cap_name = "default",
  .selector = "net.connect.v1",
  .invoke = net_connect_invoke,
  .cancel = net_cancel,
};

static const zi_async_selector sel_net_send = {
  .cap_kind = "net",
  .cap_name = "default",
  .selector = "net.send.v1",
  .invoke = net_send_invoke,
  .cancel = net_cancel,
};

static const zi_async_selector sel_net_recv = {
  .cap_kind = "net",
  .cap_name = "default",
  .selector = "net.recv.v1",
  .invoke = net_recv_invoke,
  .cancel = net_cancel,
};

__attribute__((constructor))
static void net_loop_autoreg(void) {
  zi_async_register(&sel_net_connect);
  zi_async_register(&sel_net_send);
  zi_async_register(&sel_net_recv);
}
