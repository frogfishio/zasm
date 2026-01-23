#pragma once

#include <stdint.h>

// Scan IR JSONL for repeated instruction n-grams.
//
// This is a build/analysis mode (no execution). It is intentionally a small,
// dependency-free C port of the core logic in tools/zem_repetition_scan.py.
//
// mode: "exact" or "shape"
// report_out_path: JSONL output path ("-" means stdout)
// coverage_jsonl_path: optional coverage JSONL to enrich bloat score
int zem_rep_scan_program(const char **inputs, int ninputs, int n,
                         const char *mode,
                         const char *coverage_jsonl_path,
                         const char *report_out_path,
                         int diag);
