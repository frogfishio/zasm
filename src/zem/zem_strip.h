/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Strip modes are intentionally conservative in the sense that they preserve the
// record index / PC layout by rewriting uncovered instructions rather than
// deleting them.
//
// Currently implemented mode:
//   mode == "uncovered-ret": for any instruction record whose pc has count==0
//   in the coverage profile, replace it with a single RET instruction.
//
// Inputs may be 1+ JSONL IR files; '-' means stdin.
// If ninputs==0, the caller should pass a single '-' to get stdin stream mode.
//
// out_path:
//   NULL or "-" => stdout
int zem_strip_program(const char *mode, const char **inputs, int ninputs,
                      const char *coverage_jsonl_path, const char *out_path,
                      const char *stats_out_path);

#ifdef __cplusplus
}
#endif
