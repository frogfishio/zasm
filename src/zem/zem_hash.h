/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stdint.h>

#include "jsonl.h" // record_t, recvec_t

#ifdef __cplusplus
extern "C" {
#endif

// Stable IR identity hash for conservative debloat/strip passes.
//
// Properties:
// - Deterministic across platforms/toolchains.
// - Based on the parsed IR record content (mnemonics, operands, directives,
//   labels, etc.), not on formatting.
// - Does not include loc.line.
//
// Hash function: FNV-1a 64-bit.
uint64_t zem_ir_module_hash(const recvec_t *recs);

// Incremental update helper for stream processing.
uint64_t zem_ir_module_hash_update(uint64_t h, const record_t *r);

// Return the FNV-1a 64-bit offset basis.
uint64_t zem_fnv1a64_init(void);

#ifdef __cplusplus
}
#endif
