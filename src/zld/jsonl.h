/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>

typedef enum {
  JREC_NONE = 0,
  JREC_INSTR,
  JREC_DIR,
  JREC_LABEL,
  // v1.1 additive record kinds (tooling/debugging). These must not change
  // execution semantics; consumers typically ignore them.
  JREC_META,
  JREC_SRC,
  JREC_DIAG
} rec_kind_t;

typedef enum {
  JOP_NONE = 0,
  JOP_SYM,
  JOP_REG,
  JOP_LBL,
  JOP_NUM,
  JOP_STR,
  JOP_MEM
} op_kind_t;

typedef struct {
  op_kind_t t;
  char* s;     // for SYM/STR/MEM base (heap-allocated)
  long n;      // for NUM
  long disp;   // for MEM displacement
  int size;    // for MEM size hint (bytes)
  int base_is_reg; // for MEM: 1 if base is reg, 0 otherwise
} operand_t;

typedef struct {
  // IR version tag (parsed from "ir").
  // 10 => zasm-v1.0
  // 11 => zasm-v1.1
  int ir;
  rec_kind_t k;
  int line;          // optional: from loc.line if present, else -1

  // v1.1 meta/src/diag (optional; most consumers ignore)
  long id;            // optional record id (if present), else -1
  long src_ref;       // optional source record reference (if present), else -1

  // instr
  char* m;           // mnemonic
  operand_t* ops;
  size_t nops;
  char* section;     // optional section hint (currently unused)

  // dir
  char* d;           // directive
  char* name;        // optional symbol name (for DB/DW)
  operand_t* args;
  size_t nargs;

  // label
  char* label;

  // meta
  char* producer;
  char* unit;
  char* ts;

  // src
  long src_id;        // required for k==src (schema); else -1
  long src_line;      // required for k==src (schema); else -1
  long src_col;       // optional; else -1
  char* src_file;     // optional
  char* src_text;     // optional

  // diag
  char* level;        // info|warn|error
  char* msg;
  char* code;
  char* help;
} record_t;

typedef struct {
  record_t* v;
  size_t n;
  size_t cap;
} recvec_t;

void recvec_init(recvec_t* r);
void recvec_push(recvec_t* r, record_t rec);
void recvec_free(recvec_t* r);

int parse_jsonl_record(const char* line, record_t* out); // 0=ok, nonzero=error
void record_free(record_t* r);
int validate_record_conform(const record_t* r, char* err, size_t errlen);
int validate_record_strict(const char* line, const record_t* r, char* err, size_t errlen);
