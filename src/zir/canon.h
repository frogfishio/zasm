/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdio.h>

#include "jsonl.h" // record_t, recvec_t

// Canonicalizes IR JSONL and writes it to `out`.
// If `assign_ids` is nonzero, assigns stable IDs to instr records missing `id`.
// Returns 0 on success, nonzero on error.
int zir_canon_write(FILE *out, recvec_t *recs, int assign_ids, char *err,
                    size_t errlen);
