/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../ctl_common.h"
#include "../../include/zi_async.h"
#include "files_store.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int files_debug_enabled(void) {
  return getenv("ZING_FILES_DEBUG") != NULL;
}

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
    /* scope is used as the directory path within the guest-visible FS. */
  }
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;

  char dir_path[1024];
  if (scope_len == 0) {
    /* Root. */
    if (!zi_files_map_path((const uint8_t*)"/", 1u, dir_path, sizeof(dir_path))) {
      return emit->future_fail(ctx, future_id, "t_file_io", "root");
    }
  } else {
    if (!zi_files_map_path(params + off - scope_len, scope_len, dir_path, sizeof(dir_path))) {
      return emit->future_fail(ctx, future_id, "t_file_denied", "path");
    }
  }

  DIR* d = opendir(dir_path);
  if (!d) return emit->future_fail(ctx, future_id, "t_file_not_found", "dir");
  if (files_debug_enabled()) {
    fprintf(stderr, "files.list dir=%s\n", dir_path);
  }

  typedef struct ent { char name[256]; } ent_t;
  ent_t ents[256];
  size_t nfiles = 0;

  struct dirent* de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.') continue;
    if (nfiles >= (sizeof(ents) / sizeof(ents[0]))) break;
    strncpy(ents[nfiles].name, de->d_name, sizeof(ents[nfiles].name) - 1);
    ents[nfiles].name[sizeof(ents[nfiles].name) - 1] = '\0';
    nfiles++;
  }
  closedir(d);

  for (size_t i = 0; i + 1 < nfiles; i++) {
    for (size_t j = i + 1; j < nfiles; j++) {
      if (strcmp(ents[i].name, ents[j].name) > 0) {
        ent_t tmp = ents[i];
        ents[i] = ents[j];
        ents[j] = tmp;
      }
    }
  }

  if (files_debug_enabled()) {
    fprintf(stderr, "files.list n=%zu\n", nfiles);
  }

  uint32_t payload_len = 4;
  for (size_t i = 0; i < nfiles; i++) {
    uint32_t id_len = (uint32_t)strlen(ents[i].name);
    payload_len += 4 + id_len + 4 + id_len + 4;
  }
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return 0;
  uint32_t off2 = 0;
  ctl_write_u32(payload + off2, (uint32_t)nfiles); off2 += 4;
  for (size_t i = 0; i < nfiles; i++) {
    uint32_t id_len = (uint32_t)strlen(ents[i].name);
    ctl_write_u32(payload + off2, id_len); off2 += 4;
    memcpy(payload + off2, ents[i].name, id_len); off2 += id_len;
    ctl_write_u32(payload + off2, id_len); off2 += 4;
    memcpy(payload + off2, ents[i].name, id_len); off2 += id_len;
    uint32_t flags = 0x02u; /* readable (best-effort) */
    ctl_write_u32(payload + off2, flags); off2 += 4;
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
  .cap_name = "fs",
  .selector = "files.list.v1",
  .invoke = files_list_invoke,
  .cancel = files_list_cancel,
};

__attribute__((constructor))
static void files_list_autoreg(void) {
  zi_async_register(&sel_files_list);
}
