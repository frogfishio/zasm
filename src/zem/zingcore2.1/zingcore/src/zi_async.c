/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi_async.h"

#include <string.h>

#define ZI_ASYNC_MAX 128
static const zi_async_selector* g_async[ZI_ASYNC_MAX];
static size_t g_async_count = 0;

int zi_async_register(const zi_async_selector* sel) {
  if (!sel || !sel->cap_kind || !sel->cap_name || !sel->selector) return 0;
  if (sel->cap_kind[0] == '\0' || sel->cap_name[0] == '\0' || sel->selector[0] == '\0') return 0;
  if (!sel->invoke) return 0;
  for (size_t i = 0; i < g_async_count; i++) {
    const zi_async_selector* s = g_async[i];
    if (strcmp(sel->cap_kind, s->cap_kind) == 0 &&
        strcmp(sel->cap_name, s->cap_name) == 0 &&
        strcmp(sel->selector, s->selector) == 0) {
      return 0; /* duplicate */
    }
  }
  if (g_async_count >= ZI_ASYNC_MAX) return 0;
  g_async[g_async_count++] = sel;
  return 1;
}

const zi_async_selector* zi_async_find(const char* kind, size_t kind_len,
                                       const char* name, size_t name_len,
                                       const char* selector, size_t selector_len) {
  for (size_t i = 0; i < g_async_count; i++) {
    const zi_async_selector* s = g_async[i];
    size_t klen = strlen(s->cap_kind);
    size_t nlen = strlen(s->cap_name);
    size_t slen = strlen(s->selector);
    if (klen == kind_len && nlen == name_len && slen == selector_len &&
        memcmp(s->cap_kind, kind, klen) == 0 &&
        memcmp(s->cap_name, name, nlen) == 0 &&
        memcmp(s->selector, selector, slen) == 0) {
      return s;
    }
  }
  return NULL;
}
