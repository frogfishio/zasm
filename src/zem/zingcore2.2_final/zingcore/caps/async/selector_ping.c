/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include <string.h>

static int ping_invoke(const zi_async_emit* emit, void* ctx,
                       const uint8_t* params, uint32_t params_len,
                       uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  (void)req_id;
  (void)params;
  (void)params_len;
  static const char ok[] = "ok";
  if (!emit || !emit->future_ok) return 0;
  return emit->future_ok(ctx, future_id, (const uint8_t*)ok, (uint32_t)(sizeof(ok) - 1));
}

static const zi_async_selector sel_ping = {
  .cap_kind = "async",
  .cap_name = "default",
  .selector = "ping.v1",
  .invoke = ping_invoke,
  .cancel = NULL,
};

__attribute__((constructor))
static void ping_autoreg(void) {
  zi_async_register(&sel_ping);
}
