/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "jsonl.h" // record_t, recvec_t
#include "zem.h"  // zem_symtab_t

#ifdef __cplusplus
extern "C" {
#endif

// Emit a trace-validity certificate SMT problem.
//
// The generated SMT-LIB is UNSAT iff the given trace is consistent with the
// supported subset of zem semantics (register-only LD + ALU ops).
//
// On success returns 1. On failure returns 0 and writes a human message to err.
int zem_cert_emit_smtlib(const char *out_smt2_path, const recvec_t *recs,
                         const zem_symtab_t *syms, const char *trace_jsonl_path,
                         uint64_t program_hash, const char *semantics_id,
                         uint64_t stdin_hash, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif
