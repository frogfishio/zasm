/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zem_types.h" // record_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zem_pgo_len_map zem_pgo_len_map_t;

// Tracks BC length values for selected mem ops (currently: FILL/LDIR).
// Intended for profile-guided lowering experiments.

enum {
  ZEM_PGO_LEN_OP_FILL = 1,
  ZEM_PGO_LEN_OP_LDIR = 2,
};

zem_pgo_len_map_t *zem_pgo_len_map_new(void);
void zem_pgo_len_map_free(zem_pgo_len_map_t *m);

// Note: len is the BC value observed at execution time.
void zem_pgo_len_note(zem_pgo_len_map_t *m, uint32_t pc, const record_t *r,
                      int op_kind, uint32_t len);

// Writes JSONL with summary + per-instruction hot length.
// Returns 1 on success, 0 on failure.
int zem_pgo_len_write_jsonl(const recvec_t *recs, const zem_pgo_len_map_t *m,
                           const char *out_path);

#ifdef __cplusplus
}
#endif
