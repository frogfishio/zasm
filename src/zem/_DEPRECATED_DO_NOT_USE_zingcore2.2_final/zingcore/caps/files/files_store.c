/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "files_store.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * file/fs filesystem backend (debug runtime).
 *
 * Host-mapped root:
 * - By default the guest-visible filesystem root is the host root ("/").
 * - If ZI_FS_ROOT is set, guest paths are mapped under that host folder.
 *
 * This is a host policy mechanism (translation), not a "guest sandbox" feature.
 */

static const char* k_root = "/";
static int k_inited = 0;

static int ensure_dir(const char* path) {
  if (mkdir(path, 0777) == 0) return 1;
  if (errno == EEXIST) return 1;
  return 0;
}

static int validate_path_bytes(const uint8_t* path, uint32_t path_len) {
  if (!path || path_len == 0 || path_len > 4096) return 0;
  for (uint32_t i = 0; i < path_len; i++) {
    uint8_t c = path[i];
    if (c == 0) return 0;
    if (c < 32 || c == 127) return 0;
    if (c == '\\') return 0; /* reject Windows-style separators */
  }
  return 1;
}

static int root_is_slash(const char* root) {
  return root && root[0] == '/' && root[1] == '\0';
}

static int normalize_join_under_root(const char* root,
                                     const uint8_t* path, uint32_t path_len,
                                     char* out, size_t out_cap) {
  if (!root || !path || !out || out_cap == 0) return 0;
  if (!validate_path_bytes(path, path_len)) return 0;

  /* If root is "/", allow absolute paths as-is (no traversal checks beyond bytes validation). */
  if (root_is_slash(root)) {
    if ((size_t)path_len + 1 > out_cap) return 0;
    memcpy(out, path, path_len);
    out[path_len] = '\0';
    return 1;
  }

  /* Guest path may be absolute; treat it as rooted under the host root. */
  uint32_t i = 0;
  while (i < path_len && path[i] == '/') i++;

  size_t rlen = strlen(root);
  while (rlen > 1 && root[rlen - 1] == '/') rlen--; /* strip trailing '/' */
  if (rlen + 1 >= out_cap) return 0;
  memcpy(out, root, rlen);
  size_t out_len = rlen;

  /* Build a normalized path, rejecting ".." and "." components. */
  while (i < path_len) {
    while (i < path_len && path[i] == '/') i++;
    if (i >= path_len) break;
    uint32_t start = i;
    while (i < path_len && path[i] != '/') i++;
    uint32_t clen = i - start;
    if (clen == 0) continue;
    if (clen == 1 && path[start] == '.') continue;
    if (clen == 2 && path[start] == '.' && path[start + 1] == '.') return 0;

    /* Append "/component". */
    if (out_len + 1 + (size_t)clen + 1 > out_cap) return 0;
    out[out_len++] = '/';
    memcpy(out + out_len, path + start, clen);
    out_len += clen;
  }

  if (out_len == rlen) {
    /* Empty path => map to root itself. */
    if (out_len + 1 > out_cap) return 0;
  }
  out[out_len] = '\0';
  return 1;
}

static void init_once(void) {
  if (k_inited) return;
  k_inited = 1;
  const char* env_root = getenv("ZI_FS_ROOT");
  if (env_root && env_root[0]) {
    k_root = env_root;
    /* Best-effort: create the directory if it doesn't exist. */
    (void)ensure_dir(k_root);
  }
}

const char* zi_files_root(void) {
  init_once();
  return k_root;
}

int zi_files_map_path(const uint8_t* path, uint32_t path_len, char* out, size_t out_cap) {
  init_once();
  return normalize_join_under_root(k_root, path, path_len, out, out_cap);
}

static int write_all(FILE* f, const uint8_t* data, uint32_t data_len) {
  if (!data_len) return 1;
  size_t n = fwrite(data, 1, data_len, f);
  return n == (size_t)data_len;
}

int zi_files_create(const uint8_t* id, uint32_t id_len,
                    const uint8_t* data, uint32_t data_len) {
  init_once();
  char full[1024];
  if (!zi_files_map_path(id, id_len, full, sizeof(full))) return 0;
  if (!zi_files_policy_allow("create", id, id_len, 1)) return 0;
  if (access(full, F_OK) == 0) return 0;

  FILE* f = fopen(full, "wb");
  if (!f) return 0;
  int ok = write_all(f, data, data_len);
  fclose(f);
  return ok;
}

int zi_files_overwrite(const uint8_t* id, uint32_t id_len,
                       const uint8_t* data, uint32_t data_len) {
  init_once();
  char full[1024];
  if (!zi_files_map_path(id, id_len, full, sizeof(full))) return 0;
  if (!zi_files_policy_allow("overwrite", id, id_len, 1)) return 0;
  if (access(full, F_OK) != 0) return 0;

  FILE* f = fopen(full, "wb");
  if (!f) return 0;
  int ok = write_all(f, data, data_len);
  fclose(f);
  return ok;
}

int zi_files_delete(const uint8_t* id, uint32_t id_len) {
  init_once();
  char full[1024];
  if (!zi_files_map_path(id, id_len, full, sizeof(full))) return 0;
  if (!zi_files_policy_allow("delete", id, id_len, 1)) return 0;
  return unlink(full) == 0;
}

int zi_files_truncate(const uint8_t* id, uint32_t id_len, uint32_t new_len) {
  init_once();
  char full[1024];
  if (!zi_files_map_path(id, id_len, full, sizeof(full))) return 0;
  if (!zi_files_policy_allow("truncate", id, id_len, 1)) return 0;
  return truncate(full, (off_t)new_len) == 0;
}

__attribute__((weak))
int zi_files_policy_allow(const char* op, const uint8_t* id, uint32_t id_len, int write_hint) {
  (void)op;
  (void)id;
  (void)id_len;
  (void)write_hint;
  return 1;
}
