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
 * Hardcoded sandbox root: `/tmp/zing_fs`.
 * Each process start clears `*.zing` files from the sandbox to keep tests deterministic.
 */

static const char* k_root = "/tmp/zing_fs";
static int k_inited = 0;

static int has_zing_ext(const char* name) {
  size_t len = strlen(name);
  return (len >= 5 && strcmp(name + len - 5, ".zing") == 0);
}

static int ensure_dir(const char* path) {
  if (mkdir(path, 0777) == 0) return 1;
  if (errno == EEXIST) return 1;
  return 0;
}

static int validate_id_component(const uint8_t* id, uint32_t id_len) {
  if (!id || id_len == 0 || id_len > 255) return 0;
  if (id_len == 1 && id[0] == '.') return 0;
  if (id_len == 2 && id[0] == '.' && id[1] == '.') return 0;
  for (uint32_t i = 0; i < id_len; i++) {
    uint8_t c = id[i];
    if (c == '/' || c == '\\') return 0;
    if (c < 32 || c == 127) return 0;
  }
  return 1;
}

static int safe_join(const char* root, const uint8_t* rel, uint32_t rel_len,
                     char* out, size_t cap) {
  if (!root) return 0;
  size_t rlen = strlen(root);
  if (rlen + 1 + (size_t)rel_len + 1 > cap) return 0;
  memcpy(out, root, rlen);
  out[rlen] = '/';
  memcpy(out + rlen + 1, rel, rel_len);
  out[rlen + 1 + rel_len] = '\0';
  return 1;
}

static void init_once(void) {
  if (k_inited) return;
  k_inited = 1;
  if (!ensure_dir("out")) return;
  if (!ensure_dir(k_root)) return;

  DIR* d = opendir(k_root);
  if (!d) return;
  struct dirent* de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.') continue;
    if (!has_zing_ext(de->d_name)) continue;
    char full[1024];
    if (snprintf(full, sizeof(full), "%s/%s", k_root, de->d_name) <= 0) continue;
    unlink(full);
  }
  closedir(d);
}

const char* zi_files_root(void) {
  init_once();
  return k_root;
}

static int write_all(FILE* f, const uint8_t* data, uint32_t data_len) {
  if (!data_len) return 1;
  size_t n = fwrite(data, 1, data_len, f);
  return n == (size_t)data_len;
}

int zi_files_create(const uint8_t* id, uint32_t id_len,
                    const uint8_t* data, uint32_t data_len) {
  init_once();
  if (!validate_id_component(id, id_len)) return 0;
  if (!zi_files_policy_allow("create", id, id_len, 1)) return 0;
  char full[1024];
  if (!safe_join(k_root, id, id_len, full, sizeof(full))) return 0;

  if (!has_zing_ext(full)) return 0;
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
  if (!validate_id_component(id, id_len)) return 0;
  if (!zi_files_policy_allow("overwrite", id, id_len, 1)) return 0;
  char full[1024];
  if (!safe_join(k_root, id, id_len, full, sizeof(full))) return 0;
  if (!has_zing_ext(full)) return 0;
  if (access(full, F_OK) != 0) return 0;

  FILE* f = fopen(full, "wb");
  if (!f) return 0;
  int ok = write_all(f, data, data_len);
  fclose(f);
  return ok;
}

int zi_files_delete(const uint8_t* id, uint32_t id_len) {
  init_once();
  if (!validate_id_component(id, id_len)) return 0;
  if (!zi_files_policy_allow("delete", id, id_len, 1)) return 0;
  char full[1024];
  if (!safe_join(k_root, id, id_len, full, sizeof(full))) return 0;
  if (!has_zing_ext(full)) return 0;
  return unlink(full) == 0;
}

int zi_files_truncate(const uint8_t* id, uint32_t id_len, uint32_t new_len) {
  init_once();
  if (!validate_id_component(id, id_len)) return 0;
  if (!zi_files_policy_allow("truncate", id, id_len, 1)) return 0;
  char full[1024];
  if (!safe_join(k_root, id, id_len, full, sizeof(full))) return 0;
  if (!has_zing_ext(full)) return 0;
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
