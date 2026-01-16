/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include "zem_types.h"

int zem_build_program(const char **inputs, int ninputs, recvec_t *out_recs,
                      const char ***out_pc_srcs);

int zem_build_data_and_symbols(const recvec_t *recs, zem_buf_t *mem,
                               zem_symtab_t *syms);

int zem_build_label_index(const recvec_t *recs, zem_symtab_t *labels);
