#ifndef ZASM_LOWER_MACH_O_H
#define ZASM_LOWER_MACH_O_H

#include "codegen.h"
#include "ir.h"

/* Emit a Mach-O relocatable object for macOS arm64.
 * - ir: parsed IR program
 * - blob: already codegen'd arm64 blob
 * - out_path: target .o path
 * Returns 0 on success.
 */
int macho_write_object(const ir_prog_t *ir, const cg_blob_t *blob, const char *out_path);

#endif
