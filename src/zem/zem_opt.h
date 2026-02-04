/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Rewrite IR JSONL with a small, target-independent optimization pipeline.
// This is a build step (no execution): it reads IR JSONL inputs and writes a
// new IR JSONL stream.
//
// mode:
//   - "dead-cf": remove unreachable instruction records after RET or
//                unconditional JR until the next label.
//   - "cfg-simplify": build basic blocks + a simple CFG, then remove
//                   unreachable instruction records and trivial fallthrough JRs.
//
// inputs/ninputs:
//   - One or more IR JSONL files; "-" means stdin.
//
// out_path:
//   - Output JSONL path; NULL/""/"-" => stdout.
//
// stats_out_path:
//   - Optional JSONL stats path; "-" => stderr.
int zem_opt_program(const char *mode, const char **inputs, int ninputs,
                    const char *out_path, const char *stats_out_path);

#ifdef __cplusplus
}
#endif
