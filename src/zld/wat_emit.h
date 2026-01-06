/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include "jsonl.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t offset;
  uint8_t* bytes;
  size_t len;
  char* name; // label
} data_seg_t;

typedef struct {
  data_seg_t* v;
  size_t n;
  size_t cap;
  uint32_t next_off;
} datavec_t;

void datavec_init(datavec_t* d, uint32_t start_off);
void datavec_add(datavec_t* d, const char* name, const uint8_t* bytes, size_t len);
void datavec_free(datavec_t* d);

// Builds data segments + globals map for DB/DW and emits WAT to stdout.
// mem_max_pages == 0 means no declared maximum.
// Return 0 on success, nonzero on error.
int emit_wat_module(const recvec_t* recs, size_t mem_max_pages);

// Emits a JSON manifest of exports/imports/primitives to stdout.
// Return 0 on success, nonzero on error.
int emit_manifest(const recvec_t* recs);

// Enables emitting a custom name section in WAT output.
void wat_set_emit_names(int on);
