/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
#ifndef ZING_HASH_H
#define ZING_HASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Stable 64-bit hash for identifiers used in compiled artifacts.
 * FNV-1a is simple, fast, deterministic, and easy to reimplement in host tools.
 */
uint64_t zing_hash64_fnv1a(const void *data, size_t len);
uint64_t zing_hash64_cstr(const char *s);

#endif
