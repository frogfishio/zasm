/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include <string.h>

static int net_echo_invoke(const zi_async_emit* emit, void* ctx,
                           const uint8_t* params, uint32_t params_len,
                           uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  (void)req_id;
  if (!emit || !emit->future_ok) return 0;
  return emit->future_ok(ctx, future_id, params, params_len);
}

static int net_echo_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_net_echo = {
  .cap_kind = "net",
  .cap_name = "default",
  .selector = "net.echo.v1",
  .invoke = net_echo_invoke,
  .cancel = net_echo_cancel,
};

__attribute__((constructor))
static void net_echo_autoreg(void) {
  zi_async_register(&sel_net_echo);
}
