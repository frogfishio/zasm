/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stdint.h>
#include <stdio.h>

#include "zem_types.h"

void zem_json_escape(FILE *out, const char *s);

int zem_str_ieq(const char *a, const char *b);

int zem_reg_ref(zem_regs_t *r, const char *name, uint64_t **out);

int zem_jump_to_label(const zem_symtab_t *labels, const char *label, size_t *pc);

int zem_mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len);

uint32_t zem_rotl32(uint32_t x, uint32_t r);
uint32_t zem_rotr32(uint32_t x, uint32_t r);
uint32_t zem_clz32(uint32_t x);
uint32_t zem_ctz32(uint32_t x);
uint32_t zem_popc32(uint32_t x);

uint64_t zem_rotl64(uint64_t x, uint64_t r);
uint64_t zem_rotr64(uint64_t x, uint64_t r);
uint64_t zem_clz64(uint64_t x);
uint64_t zem_ctz64(uint64_t x);
uint64_t zem_popc64(uint64_t x);
