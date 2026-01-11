/* IR structures mirroring schema/ir/v1/record.schema.json (JSONL input). */
#ifndef ZINGCC_IR_H
#define ZINGCC_IR_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  IR_OP_NONE = 0,
  IR_OP_SYM,
  IR_OP_NUM,
  IR_OP_STR,
  IR_OP_MEM,
} ir_op_kind_t;

typedef struct {
  int has_loc;
  unsigned line;
  unsigned col;
  char *unit;
} ir_loc_t;

typedef struct {
  ir_op_kind_t kind;
  /* String-bearing variants; only one is used depending on kind. */
  char *sym;       /* IR_OP_SYM */
  char *str;       /* IR_OP_STR */
  char *mem_base;  /* IR_OP_MEM */
  long long num;   /* IR_OP_NUM */
  unsigned long long unum;
  int is_unsigned;
  ir_loc_t loc;
} ir_op_t;

typedef enum {
  IR_DIR_PUBLIC,
  IR_DIR_EXTERN,
  IR_DIR_DB,
  IR_DIR_DW,
  IR_DIR_RESB,
  IR_DIR_STR,
  IR_DIR_EQU,
} ir_dir_kind_t;

typedef enum {
  IR_ENTRY_LABEL,
  IR_ENTRY_INSTR,
  IR_ENTRY_DIR,
} ir_entry_kind_t;

typedef struct ir_entry {
  ir_entry_kind_t kind;
  ir_loc_t loc;
  union {
    struct {
      char *name;
    } label;
    struct {
      char *mnem;
      ir_op_t *ops;
      size_t op_count;
    } instr;
    struct {
      ir_dir_kind_t dir_kind;
      char *name;       /* optional label on directive */
      ir_op_t *args;
      size_t arg_count;
      /* Derived/expanded data for data-producing directives (DB/DW/STR/EQU). */
      unsigned char *data;
      size_t data_len;
      size_t reserve_len; /* for RESB */
      long long equ_value;
      int has_equ_value;
      /* EXTERN-specific fields */
      char *extern_module;
      char *extern_field;
      char *extern_as;
    } dir;
  } u;
  struct ir_entry *next;
} ir_entry_t;

typedef struct {
  ir_entry_t *head;
  ir_entry_t *tail;
  int has_public_lembeh;
} ir_prog_t;

ir_entry_t *ir_entry_new(ir_entry_kind_t kind);
void ir_entry_free(ir_entry_t *e);
int ir_append_entry(ir_prog_t *p, ir_entry_t *e);

void ir_init(ir_prog_t *p);
void ir_free(ir_prog_t *p);
int ir_append_label(ir_prog_t *p, const char *label);
int ir_append_call(ir_prog_t *p, const char *sym);
int ir_append_ret(ir_prog_t *p);
int ir_append_data(ir_prog_t *p, const char *sym, const unsigned char *data, size_t len);
int ir_append_public(ir_prog_t *p, const char *sym);
int ir_append_instr(ir_prog_t *p, const char *mnem, const ir_op_t *ops, size_t op_count);

#endif
