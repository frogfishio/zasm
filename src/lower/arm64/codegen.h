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
  size_t ir_id;           /* IR record id, 0 if unspecified */
  struct cg_reloc *next;
} cg_reloc_t;

typedef struct cg_pc_map {
  uint32_t off;           /* byte offset within code */
  size_t ir_id;           /* IR record id */
  uint32_t line;          /* IR loc line (0 if none) */
  struct cg_pc_map *next;
} cg_pc_map_t;

typedef struct {
  uint64_t total_ns;
  uint64_t collect_syms_ns;
  uint64_t func_detect_ns;
  uint64_t instr_size_ns;
  uint64_t alloc_ns;
  uint64_t pass2_total_ns;
  uint64_t pass2_labels_ns;
  uint64_t pass2_dirs_ns;
  uint64_t pass2_instrs_ns;
  uint64_t finalize_ns;
  uint64_t symtab_ns;
  uint64_t reloc_ns;
  uint64_t pcmap_ns;
} cg_profile_t;

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
  cg_pc_map_t *pc_map;    /* mapping from code offsets to IR ids/lines */
  uint32_t pc_map_count;
  int profile_enabled;
  cg_profile_t prof;
} cg_blob_t;

typedef enum {
  CG_PGO_LEN_KIND_UNKNOWN = 0,
  CG_PGO_LEN_KIND_FILL = 1,
  CG_PGO_LEN_KIND_LDIR = 2,
} cg_pgo_len_kind_t;

typedef struct {
  cg_pgo_len_kind_t kind;
  uint32_t pc;            /* IR record index (includes labels/dirs), as reported by zem */
  uint32_t hot_len;
  uint64_t hot_hits;
  uint64_t total_hits;
  uint64_t other_hits;
} cg_pgo_len_site_t;

typedef struct {
  char *module_hash;      /* optional; owned by the profile */
  cg_pgo_len_site_t *sites;
  size_t site_count;
} cg_pgo_len_profile_t;

int cg_emit_arm64(const ir_prog_t *ir, cg_blob_t *out);
void cg_free(cg_blob_t *out);

/* Optional: override the implicit entry-function heuristic.
 * When set, cg_emit_arm64 will treat this label as a function entry.
 * Pass NULL to clear.
 */
void cg_set_entry_label_override(const char *label);

/* Optional: provide a zem --pgo-len-out JSONL profile to guide codegen.
 * If set, codegen may choose size-optimized implementations for bulk mem ops.
 * Pass NULL to clear.
 */
void cg_set_pgo_len_profile(const cg_pgo_len_profile_t *prof);

#endif /* ZINGCC_CODEGEN_H */
