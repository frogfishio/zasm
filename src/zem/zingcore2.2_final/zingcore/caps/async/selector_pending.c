/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"

static int pending_invoke(const zi_async_emit* emit, void* ctx,
                          const uint8_t* params, uint32_t params_len,
                          uint64_t req_id, uint64_t future_id) {
  (void)emit; (void)ctx; (void)params; (void)params_len; (void)req_id; (void)future_id;
  /* Do nothing: leaves future pending for join/cancel tests. */
  return 1;
}

static const zi_async_selector sel_pending = {
  .cap_kind = "async",
  .cap_name = "default",
  .selector = "pending.v1",
  .invoke = pending_invoke,
  .cancel = NULL,
};

__attribute__((constructor))
static void pending_autoreg(void) {
  zi_async_register(&sel_pending);
}
