/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "files_store.h"
#include <stdlib.h>
#include <string.h>

static const uint8_t k_file1[] = "hello from file a\n";
static const uint8_t k_file2[] = "second file contents\n";
static const uint8_t k_id1[] = "a.zing";
static const uint8_t k_id2[] = "b.zing";

static zi_file_entry k_files[ZI_FILES_MAX];
static size_t k_files_count = 0;
static int k_inited = 0;

static char* dup_bytes(const uint8_t* bytes, uint32_t len) {
  char* out = (char*)malloc(len + 1);
  if (!out) return NULL;
  memcpy(out, bytes, len);
  out[len] = '\0';
  return out;
}

static uint8_t* dup_data(const uint8_t* data, uint32_t len, uint32_t* out_cap) {
  uint32_t cap = (len < 16) ? 16 : len;
  uint8_t* out = (uint8_t*)malloc(cap);
  if (!out) return NULL;
  if (len) memcpy(out, data, len);
  if (out_cap) *out_cap = cap;
  return out;
}

static void zi_files_init(void) {
  if (k_inited) return;
  k_inited = 1;
  zi_files_create(k_id1, (uint32_t)(sizeof(k_id1) - 1), k_file1, (uint32_t)(sizeof(k_file1) - 1));
  zi_files_create(k_id2, (uint32_t)(sizeof(k_id2) - 1), k_file2, (uint32_t)(sizeof(k_file2) - 1));
}

size_t zi_files_count(void) {
  zi_files_init();
  return k_files_count;
}

const zi_file_entry* zi_files_get(size_t idx) {
  zi_files_init();
  if (idx >= k_files_count) return NULL;
  return &k_files[idx];
}

const zi_file_entry* zi_files_find_id(const uint8_t* id, uint32_t id_len) {
  return zi_files_find_mutable(id, id_len);
}

zi_file_entry* zi_files_find_mutable(const uint8_t* id, uint32_t id_len) {
  zi_files_init();
  for (size_t i = 0; i < k_files_count; i++) {
    size_t len = strlen(k_files[i].id);
    if (len == id_len && memcmp(k_files[i].id, id, len) == 0) return &k_files[i];
  }
  return NULL;
}

int zi_files_create(const uint8_t* id, uint32_t id_len,
                    const uint8_t* data, uint32_t data_len) {
  zi_files_init();
  if (!id || id_len == 0 || id_len > 255) return 0;
  if (k_files_count >= ZI_FILES_MAX) return 0;
  if (zi_files_find_mutable(id, id_len)) return 0;
  if (!zi_files_policy_allow("create", id, id_len, 1)) return 0;
  zi_file_entry* e = &k_files[k_files_count];
  memset(e, 0, sizeof(*e));
  e->id = dup_bytes(id, id_len);
  if (!e->id) return 0;
  e->display = dup_bytes(id, id_len);
  if (!e->display) {
    free(e->id);
    e->id = NULL;
    return 0;
  }
  e->data = dup_data(data, data_len, &e->cap);
  if (!e->data) {
    free(e->id); free(e->display);
    e->id = NULL; e->display = NULL;
    return 0;
  }
  e->len = data_len;
  k_files_count++;
  return 1;
}

int zi_files_overwrite(const uint8_t* id, uint32_t id_len,
                       const uint8_t* data, uint32_t data_len) {
  zi_file_entry* e = zi_files_find_mutable(id, id_len);
  if (!e) return 0;
  if (!zi_files_policy_allow("overwrite", id, id_len, 1)) return 0;
  uint32_t cap = 0;
  uint8_t* buf = dup_data(data, data_len, &cap);
  if (!buf) return 0;
  free(e->data);
  e->data = buf;
  e->len = data_len;
  e->cap = cap;
  return 1;
}

int zi_files_delete(const uint8_t* id, uint32_t id_len) {
  for (size_t i = 0; i < zi_files_count(); i++) {
    size_t len = strlen(k_files[i].id);
    if (len == id_len && memcmp(k_files[i].id, id, len) == 0) {
      if (!zi_files_policy_allow("delete", id, id_len, 1)) return 0;
      free(k_files[i].id);
      free(k_files[i].display);
      free(k_files[i].data);
      for (size_t j = i + 1; j < k_files_count; j++) {
        k_files[j - 1] = k_files[j];
      }
      k_files_count--;
      return 1;
    }
  }
  return 0;
}

int zi_files_truncate(const uint8_t* id, uint32_t id_len, uint32_t new_len) {
  zi_file_entry* e = zi_files_find_mutable(id, id_len);
  if (!e) return 0;
  if (!zi_files_policy_allow("truncate", id, id_len, 1)) return 0;
  if (new_len > e->cap) {
    uint32_t new_cap = e->cap;
    while (new_cap < new_len) new_cap = (new_cap < 1024) ? (new_cap * 2) : (new_cap + 1024);
    uint8_t* nd = (uint8_t*)realloc(e->data, new_cap);
    if (!nd) return 0;
    e->data = nd;
    e->cap = new_cap;
  }
  if (new_len > e->len) {
    memset(e->data + e->len, 0, new_len - e->len);
  }
  e->len = new_len;
  return 1;
}

__attribute__((weak))
int zi_files_policy_allow(const char* op, const uint8_t* id, uint32_t id_len, int write_hint) {
  (void)op; (void)id; (void)id_len; (void)write_hint;
  return 1;
}
