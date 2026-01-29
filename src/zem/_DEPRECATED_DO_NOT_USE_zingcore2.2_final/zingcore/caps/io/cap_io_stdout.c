/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../ctl_common.h"
#include "../../include/zi_caps.h"

static int cap_io_stdout_describe(uint8_t* out, size_t cap,
                                  uint16_t op, uint32_t rid,
                                  const uint8_t* payload, uint32_t payload_len) {
  (void)payload;
  (void)payload_len;
  /* Minimal describe: ok + no flags + no schema. */
  uint8_t pl[12];
  pl[0] = 1; pl[1] = 0; pl[2] = 0; pl[3] = 0; /* ok */
  ctl_write_u32(pl + 4, 0); /* cap_flags */
  ctl_write_u32(pl + 8, 0); /* schema len */
  return ctl_write_ok(out, cap, op, rid, pl, sizeof(pl));
}

static const zi_cap_v1 cap_io_stdout_v1 = {
  .kind = "io",
  .name = "stdout",
  .version = 1,
  .cap_flags = 0,
  .meta = NULL,
  .meta_len = 0,
  .describe = cap_io_stdout_describe,
  .open = NULL,
};

__attribute__((constructor))
static void cap_io_stdout_register(void) {
  zi_cap_register(&cap_io_stdout_v1);
}

