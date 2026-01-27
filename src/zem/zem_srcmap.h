/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zem_types.h"

typedef struct {
  uint32_t id;
  const char *file;  // points into parsed IR (record_t strings)
  int32_t line;
  int32_t col;
  const char *text;  // points into parsed IR (record_t strings)
} zem_src_entry_t;

// Lightweight open-addressing map: src_id (u32) -> entry index.
//
// Notes:
// - We store pointers into the parsed IR records; the srcmap must not outlive
//   the recvec_t it was built from.
// - Lookup is O(1) expected.
typedef struct {
  zem_src_entry_t *entries;
  size_t n;
  size_t cap;

  // hash table; slot is empty when vals[i] == 0
  uint32_t *keys;
  uint32_t *vals;  // entry index + 1
  size_t map_cap;
} zem_srcmap_t;

void zem_srcmap_init(zem_srcmap_t *m);
void zem_srcmap_free(zem_srcmap_t *m);

int zem_srcmap_add(zem_srcmap_t *m, uint32_t id, const char *file, int32_t line,
                   int32_t col, const char *text);

const zem_src_entry_t *zem_srcmap_get(const zem_srcmap_t *m, uint32_t id);

// Find the first instruction PC whose src_ref resolves to a src record with
// matching file and line.
//
// If `file` contains '/', match against src.file exactly.
// Otherwise, match against basename(src.file) or src.file.
int zem_srcmap_find_pc(const recvec_t *recs, const zem_srcmap_t *m,
                       const char *file, int32_t line, size_t *out_pc);
