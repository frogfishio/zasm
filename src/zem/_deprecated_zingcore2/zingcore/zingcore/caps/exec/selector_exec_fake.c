/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include <string.h>

static int exec_fake_invoke(const zi_async_emit* emit, void* ctx,
                            const uint8_t* params, uint32_t params_len,
                            uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  (void)params;
  (void)params_len;
  (void)req_id;
  static const char ok[] = "exec-ok";
  if (!emit || !emit->future_ok) return 0;
  return emit->future_ok(ctx, future_id, (const uint8_t*)ok, (uint32_t)(sizeof(ok) - 1));
}

static int exec_fake_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_exec_fake = {
  .cap_kind = "exec",
  .cap_name = "default",
  .selector = "exec.fake.v1",
  .invoke = exec_fake_invoke,
  .cancel = exec_fake_cancel,
};

__attribute__((constructor))
static void exec_fake_autoreg(void) {
  zi_async_register(&sel_exec_fake);
}
