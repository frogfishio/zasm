/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include "zem_types.h"

#include "zem_srcmap.h"

int zem_exec_program(const recvec_t *recs, zem_buf_t *mem,
                     const zem_symtab_t *syms, const zem_symtab_t *labels,
                     const zem_dbg_cfg_t *dbg_cfg, const char *const *pc_srcs,
                     const zem_srcmap_t *srcmap,
                     const zem_proc_t *proc,
                     const char *stdin_source_name);
