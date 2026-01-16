/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

// Small shared diagnostics emitter.
//
// Goals:
// - Human-friendly output by default.
// - Machine-readable JSONL with --json (one object per line on stderr).
// - Stable schema for editor integration.

// Configure output mode.
void diag_set_tool(const char* tool);
void diag_set_verbose(int on);
void diag_set_json(int on);

// Optional source context (used when callers don't have an explicit file).
void diag_set_source(const char* path);

int diag_is_json(void);

// Emit a diagnostic.
// - level: "error" | "warn" | "info"
// - file: may be NULL; if NULL, diag_set_source() is used if set
// - line/col are 1-based; pass 0/0 if unknown
void diag_emitf(const char* level, const char* file, int line, int col, const char* fmt, ...);

// Convenience: defaults col to 1.
void diag_emit(const char* level, const char* file, int line, const char* fmt, ...);

