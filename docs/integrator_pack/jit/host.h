/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>
#include <stdint.h>
#include "lembeh_cloak.h"

typedef struct {
  uint8_t* mem;
  size_t mem_cap;
  uint64_t mem_cap_bytes;
  int trace;
  int strict;
  int faulted;
  char fault_msg[160];
  lembeh_bump_alloc_t bump;
  size_t* allocs;
  size_t allocs_n;
  size_t allocs_cap;
} zcloak_env_t;

void zcloak_env_init(zcloak_env_t* env, uint8_t* mem, size_t mem_cap,
                     uint64_t mem_cap_bytes, int trace, int strict);
const lembeh_host_vtable_t* zcloak_host_vtable(void);
int zcloak_env_faulted(const zcloak_env_t* env, const char** out_msg);
