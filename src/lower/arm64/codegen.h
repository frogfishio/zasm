#ifndef ZINGCC_CODEGEN_H
#define ZINGCC_CODEGEN_H

#include <stddef.h>
#include <stdint.h>
#include "ir.h"

/* Simple symbol table entry for generated code/data. */
typedef struct symtab_entry {
  char *name;
  size_t off;             /* offset within code+data blob; code < code_len, data >= code_len */
  struct symtab_entry *next;
} symtab_entry;

/* Relocation record emitted by codegen. */
typedef struct cg_reloc {
  uint32_t instr_off;     /* byte offset within code section */
  uint32_t type;          /* 0=ADRP_PAGE, 1=ADD_PAGEOFF, 2=BRANCH26 */
  char *sym;              /* symbol name */
  uint32_t line;          /* source line for diagnostics */
  struct cg_reloc *next;
} cg_reloc_t;

/* Codegen output blob consumed by Mach-O writer. */
typedef struct {
  unsigned char *code;
  size_t code_len;
  unsigned char *data;
  size_t data_len;
  size_t data_off;        /* offset of data (code_len) for convenience */
  symtab_entry *syms;     /* linked list of symbols */
  cg_reloc_t *relocs;     /* linked list of relocations */
  uint32_t reloc_count;
} cg_blob_t;

int cg_emit_arm64(const ir_prog_t *ir, cg_blob_t *out);
void cg_free(cg_blob_t *out);

#endif /* ZINGCC_CODEGEN_H */
