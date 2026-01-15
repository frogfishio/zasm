/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../ctl_common.h"
#include "../../include/zi_async.h"
#include "files_store.h"
#include <string.h>

static int files_truncate_invoke(const zi_async_emit* emit, void* ctx,
                                 const uint8_t* params, uint32_t params_len,
                                 uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  uint32_t off = 0;
  if (params_len < 4) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "id len");
  }
  uint32_t id_len = ctl_read_u32(params + off); off += 4;
  if (off + id_len + 4 > params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "id bytes");
  }
  const uint8_t* id = params + off;
  off += id_len;
  if (off + 4 != params_len) {
    return emit->future_fail(ctx, future_id, "t_async_bad_params", "len");
  }
  uint32_t new_len = ctl_read_u32(params + off);
  if (!zi_files_truncate(id, id_len, new_len)) {
    return emit->future_fail(ctx, future_id, "t_file_not_found", "id");
  }
  return emit->future_ok(ctx, future_id, NULL, 0);
}

static int files_truncate_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_truncate = {
  .cap_kind = "file",
  .cap_name = "view",
  .selector = "files.truncate.v1",
  .invoke = files_truncate_invoke,
  .cancel = files_truncate_cancel,
};

__attribute__((constructor))
static void files_truncate_autoreg(void) {
  zi_async_register(&sel_files_truncate);
}
