/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "ctl_common.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct files_ctx {
  const char* root; /* sandbox root (cwd if NULL) */
} files_ctx_t;

static int safe_join(const char* root, const char* rel, char* out, size_t cap) {
  if (!root) root = ".";
  size_t rlen = strlen(root);
  size_t llen = strlen(rel);
  if (rlen + 1 + llen + 1 > cap) return -1;
  memcpy(out, root, rlen);
  out[rlen] = '/';
  memcpy(out + rlen + 1, rel, llen);
  out[rlen + 1 + llen] = '\0';
  return 0;
}

static int has_zing_ext(const char* name) {
  size_t len = strlen(name);
  return (len >= 5 && strcmp(name + len - 5, ".zing") == 0);
}

static int list_dir(files_ctx_t* ctx, uint8_t* out, size_t cap, uint16_t op, uint32_t rid) {
  char rootbuf[1024];
  const char* root = ctx->root ? ctx->root : (getcwd(rootbuf, sizeof(rootbuf)) ? rootbuf : ".");
  DIR* d = opendir(root);
  if (!d) return ctl_write_error(out, cap, op, rid, "t_file_not_found", "dir");

  /* Collect entries first to size the payload deterministically. */
  typedef struct ent { char name[256]; uint32_t flags; } ent_t;
  ent_t ents[256];
  size_t n = 0;
  struct dirent* de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.') continue; /* skip hidden/.. */
    if (!has_zing_ext(de->d_name)) continue; /* only .zing */
    if (n >= sizeof(ents)/sizeof(ents[0])) break;
    strncpy(ents[n].name, de->d_name, sizeof(ents[n].name) - 1);
    ents[n].name[sizeof(ents[n].name) - 1] = '\0';
    ents[n].flags = 1u << 0; /* is_dir=0, readable=1 */
    n++;
  }
  closedir(d);

  /* Sort deterministically by (name). */
  for (size_t i = 0; i + 1 < n; i++) {
    for (size_t j = i + 1; j < n; j++) {
      if (strcmp(ents[j].name, ents[i].name) < 0) {
        ent_t tmp = ents[i]; ents[i] = ents[j]; ents[j] = tmp;
      }
    }
  }

  /* Payload: H4 n, then repeat (HBYTES id, HSTR display, H4 flags). id = name. */
  size_t payload_len = 4;
  for (size_t i = 0; i < n; i++) {
    size_t id_len = strlen(ents[i].name);
    payload_len += 4 + id_len + 4 + id_len + 4;
  }
  if (cap < 20 + payload_len) return -1;
  uint8_t* p = out + 20;
  ctl_write_u32(p, (uint32_t)n); p += 4;
  for (size_t i = 0; i < n; i++) {
    size_t id_len = strlen(ents[i].name);
    ctl_write_u32(p, (uint32_t)id_len); p += 4;
    memcpy(p, ents[i].name, id_len); p += id_len;
    ctl_write_u32(p, (uint32_t)id_len); p += 4;
    memcpy(p, ents[i].name, id_len); p += id_len;
    ctl_write_u32(p, ents[i].flags); p += 4;
  }
  return ctl_write_ok(out, cap, op, rid, out + 20, (uint32_t)payload_len);
}

static int open_path(files_ctx_t* ctx, const uint8_t* payload, uint32_t plen,
                     uint8_t* out, size_t cap, uint16_t op, uint32_t rid, ctl_handles_t* handles) {
  /* CAPS_OPEN variant 2: H1 variant=2, HSTR path, H4 mode; mode must be READ only. */
  if (plen < 1 + 4 + 4) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "payload");
  uint8_t variant = payload[0];
  if (variant != 2) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "variant");
  uint32_t path_len = ctl_read_u32(payload + 1);
  if (1 + 4 + path_len + 4 > plen) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "path");
  const char* path = (const char*)(payload + 5);
  uint32_t mode = ctl_read_u32(payload + 1 + 4 + path_len);
  /* mode bit0=READ, others denied */
  if ((mode & ~1u) != 0) return ctl_write_error(out, cap, op, rid, "t_file_not_readable", "mode");
  char full[1024];
  if (safe_join(ctx->root, path, full, sizeof(full)) != 0) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "pathlen");
  if (!has_zing_ext(full)) return ctl_write_error(out, cap, op, rid, "t_file_not_found", "ext");
  struct stat st;
  if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) return ctl_write_error(out, cap, op, rid, "t_file_not_found", "stat");
  FILE* f = fopen(full, "rb");
  if (!f) return ctl_write_error(out, cap, op, rid, "t_file_not_readable", strerror(errno));
  /* We won't stream; instead we pack the file contents into a fresh handle-backed buffer. */
  uint8_t* buf = (uint8_t*)malloc((size_t)st.st_size);
  size_t rd = fread(buf, 1, (size_t)st.st_size, f);
  fclose(f);
  if (rd != (size_t)st.st_size) { free(buf); return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "short read"); }
  /* For simplicity, return handle=id and inline payload: H4 handle, H4 hflags, H4 len, bytes. */
  uint32_t h = ctl_handle_alloc(handles);
  if (!h) { free(buf); return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "handles"); }
  uint32_t payload_len = 4 + 4 + 4 + (uint32_t)rd;
  if (cap < 20 + payload_len) { free(buf); return -1; }
  uint8_t* p = out + 20;
  ctl_write_u32(p, h); p += 4;
  ctl_write_u32(p, 1u); p += 4; /* readable */
  ctl_write_u32(p, (uint32_t)rd); p += 4;
  memcpy(p, buf, rd);
  int n = ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
  free(buf);
  return n;
}

int cap_files_handle(files_ctx_t* ctx, uint16_t op, const ctl_frame_t* fr,
                     uint8_t* out, size_t cap, ctl_handles_t* handles) {
  /* file list op=10, open op=11, CAPS_OPEN alias also uses op=11 via variant */
  if (op == 10) return list_dir(ctx, out, cap, fr->op, fr->rid);
  if (op == 11) return open_path(ctx, fr->payload, fr->payload_len, out, cap, fr->op, fr->rid, handles);
  return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "unknown file op");
}
