#pragma once

#include <stdint.h>

// Returns a malloc'd string like "fnv1a64:0123456789abcdef".
// Uses the same identity hash as zem (record/operand canonicalization).
// Returns NULL on error.
char *lower_ir_module_hash_str_from_jsonl_path(const char *path);
