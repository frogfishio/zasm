/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"
#include "files_store.h"
#include <stdlib.h>
#include <string.h>

static int files_list_invoke(const zi_async_emit* emit, void* ctx,
                             const uint8_t* params, uint32_t params_len,
                             uint64_t req_id, uint64_t future_id) {
  (void)ctx;
  /* Params: HSTR scope. */
  uint32_t off = 0;
  if (params_len < 4) {
    if (emit && emit->fail) emit->fail(ctx, req_id, "t_async_bad_params", "scope");
    return 1;
  }
  uint32_t scope_len = (uint32_t)params[0] | ((uint32_t)params[1] << 8) |
                       ((uint32_t)params[2] << 16) | ((uint32_t)params[3] << 24);
  off += 4;
  if (off + scope_len != params_len) {
    if (emit && emit->fail) emit->fail(ctx, req_id, "t_async_bad_params", "scope len");
    return 1;
  }
  if (scope_len != 0) {
    if (emit && emit->fail) emit->fail(ctx, req_id, "t_file_denied", "scope");
    return 1;
  }
  (void)req_id;
  if (!emit || !emit->future_ok) return 0;
  /* Build list payload from store. */
  size_t nfiles = zi_files_count();
  /* Sort by display/id lexicographically. */
  const zi_file_entry* entries[ZI_FILES_MAX];
  for (size_t i = 0; i < nfiles; i++) entries[i] = zi_files_get(i);
  for (size_t i = 0; i + 1 < nfiles; i++) {
    for (size_t j = i + 1; j < nfiles; j++) {
      if (strcmp(entries[i]->display, entries[j]->display) > 0) {
        const zi_file_entry* tmp = entries[i];
        entries[i] = entries[j];
        entries[j] = tmp;
      }
    }
  }
  uint32_t payload_len = 4; /* n */
  for (size_t i = 0; i < nfiles; i++) {
    const zi_file_entry* e = entries[i];
    uint32_t id_len = (uint32_t)strlen(e->id);
    uint32_t disp_len = (uint32_t)strlen(e->display);
    payload_len += 4 + id_len + 4 + disp_len + 4;
  }
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return 0;
  uint32_t off2 = 0;
  payload[off2++] = (uint8_t)(nfiles & 0xFF);
  payload[off2++] = (uint8_t)((nfiles >> 8) & 0xFF);
  payload[off2++] = (uint8_t)((nfiles >> 16) & 0xFF);
  payload[off2++] = (uint8_t)((nfiles >> 24) & 0xFF);
  for (size_t i = 0; i < nfiles; i++) {
    const zi_file_entry* e = entries[i];
    uint32_t id_len = (uint32_t)strlen(e->id);
    uint32_t disp_len = (uint32_t)strlen(e->display);
    payload[off2++] = (uint8_t)(id_len & 0xFF);
    payload[off2++] = (uint8_t)((id_len >> 8) & 0xFF);
    payload[off2++] = (uint8_t)((id_len >> 16) & 0xFF);
    payload[off2++] = (uint8_t)((id_len >> 24) & 0xFF);
    memcpy(payload + off2, e->id, id_len); off2 += id_len;
    payload[off2++] = (uint8_t)(disp_len & 0xFF);
    payload[off2++] = (uint8_t)((disp_len >> 8) & 0xFF);
    payload[off2++] = (uint8_t)((disp_len >> 16) & 0xFF);
    payload[off2++] = (uint8_t)((disp_len >> 24) & 0xFF);
    memcpy(payload + off2, e->display, disp_len); off2 += disp_len;
    payload[off2++] = 0x02; payload[off2++] = 0x00; payload[off2++] = 0x00; payload[off2++] = 0x00; /* readable */
  }
  int ok = emit->future_ok(ctx, future_id, payload, payload_len);
  free(payload);
  return ok;
}

static int files_list_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  (void)future_id;
  return 1;
}

static const zi_async_selector sel_files_list = {
  .cap_kind = "file",
  .cap_name = "view",
  .selector = "files.list.v1",
  .invoke = files_list_invoke,
  .cancel = files_list_cancel,
};

__attribute__((constructor))
static void files_list_autoreg(void) {
  zi_async_register(&sel_files_list);
}
