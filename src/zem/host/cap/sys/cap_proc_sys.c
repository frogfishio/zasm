/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "ctl_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* proc: argv/env/cwd/hostname/uidgid */
static int proc_env(uint8_t* out, size_t cap, uint16_t op, uint32_t rid) {
  extern char **environ;
  uint32_t n = 0; size_t total = 0;
  for (char** p = environ; p && *p; p++) {
    const char* kv = *p;
    const char* eq = strchr(kv, '=');
    if (!eq) continue;
    size_t klen = (size_t)(eq - kv);
    size_t vlen = strlen(eq + 1);
    total += 4 + klen + 4 + vlen;
    n++;
  }
  uint32_t payload_len = 4 + total;
  uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  uint8_t* payload = out + 20;
  ctl_write_u32(payload, n); payload += 4;
  for (char** p = environ; p && *p; p++) {
    const char* kv = *p;
    const char* eq = strchr(kv, '=');
    if (!eq) continue;
    size_t klen = (size_t)(eq - kv);
    size_t vlen = strlen(eq + 1);
    ctl_write_u32(payload, (uint32_t)klen); payload += 4;
    memcpy(payload, kv, klen); payload += klen;
    ctl_write_u32(payload, (uint32_t)vlen); payload += 4;
    memcpy(payload, eq + 1, vlen); payload += vlen;
  }
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

static int proc_argv(uint8_t* out, size_t cap, uint16_t op, uint32_t rid, int argc, char** argv) {
  uint32_t n = (uint32_t)argc;
  size_t total = 4;
  for (int i = 0; i < argc; i++) total += 4 + strlen(argv[i]);
  uint32_t payload_len = (uint32_t)total;
  uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  uint8_t* payload = out + 20;
  ctl_write_u32(payload, n); payload += 4;
  for (int i = 0; i < argc; i++) {
    size_t len = strlen(argv[i]);
    ctl_write_u32(payload, (uint32_t)len); payload += 4;
    memcpy(payload, argv[i], len); payload += len;
  }
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

static int proc_cwd(uint8_t* out, size_t cap, uint16_t op, uint32_t rid) {
  char buf[1024];
  if (!getcwd(buf, sizeof(buf))) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "cwd");
  size_t len = strlen(buf);
  uint32_t payload_len = 4 + (uint32_t)len;
  if (cap < 20 + payload_len) return -1;
  uint8_t* payload = out + 20;
  ctl_write_u32(payload, (uint32_t)len); payload += 4;
  memcpy(payload, buf, len);
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

static int proc_hostname(uint8_t* out, size_t cap, uint16_t op, uint32_t rid) {
  char buf[256];
  if (gethostname(buf, sizeof(buf)) != 0) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "hostname");
  size_t len = strnlen(buf, sizeof(buf));
  uint32_t payload_len = 4 + (uint32_t)len;
  if (cap < 20 + payload_len) return -1;
  uint8_t* payload = out + 20;
  ctl_write_u32(payload, (uint32_t)len); payload += 4;
  memcpy(payload, buf, len);
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

static int proc_uidgid(uint8_t* out, size_t cap, uint16_t op, uint32_t rid) {
  uint32_t payload_len = 8;
  if (cap < 20 + payload_len) return -1;
  uint8_t* payload = out + 20;
  ctl_write_u32(payload, (uint32_t)getuid());
  ctl_write_u32(payload + 4, (uint32_t)getgid());
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

static const uint8_t platform_str[] = "mac";
static const uint8_t arch_str[] = "arm64";

static int sys_info(uint8_t* out, size_t cap, uint16_t op, uint32_t rid) {
  uint32_t cpu_count = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
  uint64_t mem_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * (uint64_t)sysconf(_SC_PAGE_SIZE);
  uint32_t plat_len = (uint32_t)sizeof(platform_str) - 1;
  uint32_t arch_len = (uint32_t)sizeof(arch_str) - 1;
  uint32_t payload_len = 4 + 8 + 4 + plat_len + 4 + arch_len;
  if (cap < 20 + payload_len) return -1;
  uint8_t* payload = out + 20;
  ctl_write_u32(payload, cpu_count); payload += 4;
  memcpy(payload, &mem_bytes, 8); payload += 8;
  ctl_write_u32(payload, plat_len); payload += 4;
  memcpy(payload, platform_str, plat_len); payload += plat_len;
  ctl_write_u32(payload, arch_len); payload += 4;
  memcpy(payload, arch_str, arch_len);
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

int cap_proc_sys_handle(uint16_t op, const ctl_frame_t* fr, uint8_t* out, size_t cap,
                        int argc, char** argv) {
  /* Map ops: proc ENV=1, ARGV=2, CWD=3, HOSTNAME=4, UIDGID=5; sys INFO=1 */
  if (op == 1 && fr->payload_len == 0) return sys_info(out, cap, fr->op, fr->rid);
  if (fr->payload_len != 0) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "payload");
  switch (op) {
    case 1: return proc_env(out, cap, fr->op, fr->rid);
    case 2: return proc_argv(out, cap, fr->op, fr->rid, argc, argv);
    case 3: return proc_cwd(out, cap, fr->op, fr->rid);
    case 4: return proc_hostname(out, cap, fr->op, fr->rid);
    case 5: return proc_uidgid(out, cap, fr->op, fr->rid);
    default:
      return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "unknown proc op");
  }
}
